package scamp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"

	"strconv"

	"fmt"
	"strings"

	"sync"

	"net"
	u "net/url"
)

// ServiceProxyDiscoveryExtension Example:
// {"vmin":0,"vmaj":4,"acsec":[[7,"background"]],"acname":["_evaluate","_execute","_evaluate","_execute","_munge","_evaluate","_execute"],"acver":[[7,1]],"acenv":[[7,"json,jsonstore,extdirect"]],"acflag":[[7,""]],"acns":[[2,"Channel.Amazon.FeedInterchange"],[3,"Channel.Amazon.InvPush"],[2,"Channel.Amazon.OrderImport"]]}
type ServiceProxyDiscoveryExtension struct {
	Vmin   int           `json:"vmin"`
	Vmaj   int           `json:"vmaj"`
	AcSec  []interface{} `json:"acsec"`
	AcName []interface{} `json:"acname"`
	AcVer  []interface{} `json:"acver"`
	AcEnv  []interface{} `json:"acenv"`
	AcFlag []interface{} `json:"acflag"`
	AcNs   []interface{} `json:"acns"`
}

type serviceProxy struct {
	version          int
	ident            string
	sector           string
	weight           int
	announceInterval int
	connspec         string
	protocols        []string
	classes          []serviceProxyClass
	extension        *ServiceProxyDiscoveryExtension
	rawClassRecords  []byte
	rawCert          []byte
	rawSig           []byte
	timestamp        highResTimestamp
	clientM          sync.Mutex
	client           *Client
}

func (sp *serviceProxy) GetClient() (client *Client, err error) {
	sp.clientM.Lock()
	defer sp.clientM.Unlock()

	//TODO: what really needs to happen is the removal of closed client from sp.client. Checking `sp.client.isClosed` is a bandaid
	if sp.client == nil || sp.client.isClosed {
		var url *u.URL
		url, err = u.Parse(sp.connspec)
		if err != nil {
			return nil, err
		}

		sp.client, err = Dial(url.Host)
		if err != nil {
			return
		}
	}

	if sp.client == nil {
		return nil, fmt.Errorf("service proxy has a nil client")
	}

	client = sp.client
	//using ident so that we can set the service proxy's client to nil in client.Close()
	client.spIdent = sp.ident

	return
}

func (sp *serviceProxy) Ident() string {
	return sp.ident
}

func (sp *serviceProxy) baseIdent() string {
	baseAndRest := strings.SplitN(sp.ident, ":", 2)
	if len(baseAndRest) != 2 {
		return sp.ident
	}
	return baseAndRest[0]
}

func (sp *serviceProxy) shortHostname() string {
	url, err := u.Parse(sp.connspec)
	if err != nil {
		log.Fatal(err)
	}

	hostParts := strings.Split(url.Host, ":")
	if len(hostParts) != 2 {
		return sp.connspec
	}
	host := hostParts[0]

	names, err := net.LookupAddr(host)
	if err != nil {
		return host
	} else if len(names) == 0 {
		return host
	}

	return names[0]
}

func (sp *serviceProxy) ConnSpec() string {
	return sp.connspec
}

func (sp *serviceProxy) Sector() string {
	return sp.sector
}

func (sp *serviceProxy) Classes() []serviceProxyClass {
	return sp.classes
}

type serviceProxyClass struct {
	className string
	actions   []actionDescription
}

func (spc serviceProxyClass) Name() string {
	return spc.className
}

func (spc serviceProxyClass) Actions() []actionDescription {
	return spc.actions
}

type actionDescription struct {
	actionName string
	crudTags   string
	version    int
}

func (ad actionDescription) Name() string {
	return ad.actionName
}

func (ad actionDescription) Version() int {
	return ad.version
}

func serviceAsServiceProxy(serv *Service) (sp *serviceProxy) {
	sp = new(serviceProxy)
	sp.version = 3
	sp.ident = serv.name
	sp.sector = serv.sector
	sp.weight = 1
	sp.announceInterval = defaultAnnounceInterval * 500
	sp.connspec = fmt.Sprintf("beepish+tls://%s:%d", serv.listenerIP.To4().String(), serv.listenerPort)
	sp.protocols = make([]string, 1, 1)
	sp.protocols[0] = "json"
	sp.classes = make([]serviceProxyClass, 0)
	sp.rawClassRecords = []byte("rawClassRecords")
	sp.rawCert = []byte("rawCert")
	sp.rawSig = []byte("rawSig")

	// { "Logger.info": [{ "name": "blah", "callback": foo() }] }
	for classAndActionName, serviceAction := range serv.actions {
		actionDotIndex := strings.LastIndex(classAndActionName, ".")
		// TODO: this is the only spot that could fail? shouldn't happen in any usage...
		if actionDotIndex == -1 {
			panic(fmt.Sprintf("bad action name: `%s` (no dot found)", classAndActionName))
		}
		className := classAndActionName[0:actionDotIndex]

		actionName := classAndActionName[actionDotIndex+1 : len(classAndActionName)]

		newServiceProxyClass := serviceProxyClass{
			className: className,
			actions:   make([]actionDescription, 0),
		}

		newServiceProxyClass.actions = append(newServiceProxyClass.actions, actionDescription{
			actionName: actionName,
			crudTags:   serviceAction.crudTags,
			version:    serviceAction.version,
		})

		sp.classes = append(sp.classes, newServiceProxyClass)

	}

	timestamp, err := getTimeOfDay()
	if err != nil {
		// Error.Printf("error with high-res timestamp: `%s`", err)
		return nil
	}
	sp.timestamp = timestamp

	return
}

func newServiceProxy(classRecordsRaw []byte, certRaw []byte, sigRaw []byte) (sp *serviceProxy, err error) {
	sp = new(serviceProxy)
	sp.rawClassRecords = classRecordsRaw
	sp.rawCert = certRaw
	sp.rawSig = sigRaw
	sp.protocols = make([]string, 0)

	var classRecords []json.RawMessage
	err = json.Unmarshal(classRecordsRaw, &classRecords)
	if err != nil {
		return
	}
	if len(classRecords) != 9 {
		err = fmt.Errorf("expected 9 entries in class record, got %d", len(classRecords))
	}

	// OMG, position-based, heterogenously typed values in an array suck to deal with.
	err = json.Unmarshal(classRecords[0], &sp.version)
	if err != nil {
		return
	}

	err = json.Unmarshal(classRecords[1], &sp.ident)
	if err != nil {
		return
	}

	err = json.Unmarshal(classRecords[2], &sp.sector)
	if err != nil {
		return
	}

	err = json.Unmarshal(classRecords[3], &sp.weight)
	if err != nil {
		return
	}

	err = json.Unmarshal(classRecords[4], &sp.announceInterval)
	if err != nil {
		return
	}

	err = json.Unmarshal(classRecords[5], &sp.connspec)
	if err != nil {
		return
	}

	var rawProtocols []*json.RawMessage
	err = json.Unmarshal(classRecords[6], &rawProtocols)
	if err != nil {
		return
	}

	// Skip object-looking stuff. We only care about strings for now
	for _, rawProtocol := range rawProtocols {
		var tempStr string
		err := json.Unmarshal(*rawProtocol, &tempStr)
		if err != nil {

			var extension ServiceProxyDiscoveryExtension
			err = json.Unmarshal(*rawProtocol, &extension)
			if err != nil {
				Error.Printf("could not parse rawProtocol: %s\n", string(*rawProtocol))
				continue
			}

			sp.extension = &extension
		} else {
			sp.protocols = append(sp.protocols, tempStr)
		}
	}

	// fmt.Printf("sp.protocols: %s\n", sp.protocols)

	var rawClasses [][]json.RawMessage
	err = json.Unmarshal(classRecords[7], &rawClasses)
	if err != nil {
		return
	}
	classes := make([]serviceProxyClass, len(rawClasses), len(rawClasses))
	sp.classes = classes

	for i, rawClass := range rawClasses {
		if len(rawClass) < 2 {
			err = fmt.Errorf("expected rawClass to have at least 2 entries. was: `%s`", rawClass)
			return nil, err
		}

		err = json.Unmarshal(rawClass[0], &classes[i].className)
		if err != nil {
			return nil, err
		}

		rawActionsSlice := rawClass[1:]
		classes[i].actions = make([]actionDescription, len(rawActionsSlice), len(rawActionsSlice))

		for j, rawActionSpec := range rawActionsSlice {
			var actionsRawMessages []json.RawMessage
			err = json.Unmarshal(rawActionSpec, &actionsRawMessages)
			if err != nil {
				Error.Printf("could not parse rawActionSpec: %s", rawActionSpec)
				return nil, err
			} else if len(actionsRawMessages) != 2 && len(actionsRawMessages) != 3 {
				err = fmt.Errorf("expected action spec to have 2 or 3 entries. got `%s` (%d)", actionsRawMessages, len(actionsRawMessages))
			}

			err = json.Unmarshal(actionsRawMessages[0], &classes[i].actions[j].actionName)
			if err != nil {
				return nil, err
			}

			err = json.Unmarshal(actionsRawMessages[1], &classes[i].actions[j].crudTags)
			if err != nil {
				return nil, err
			}

			// TODO: it's gross that some of the services announce version
			// as a string.
			if len(actionsRawMessages) < 3 {
				// TODO: safe to assume a version-less thing is version 0?
				classes[i].actions[j].version = 1
			} else {
				err = json.Unmarshal(actionsRawMessages[2], &classes[i].actions[j].version)
				if err != nil {
					var versionStr string
					err = json.Unmarshal(actionsRawMessages[2], &versionStr)
					if err != nil {
						return nil, err
					}

					versionInt, err := strconv.ParseInt(versionStr, 10, 64)
					if err != nil {
						return nil, err
					}

					classes[i].actions[j].version = int(versionInt)
				}
			}
		}
	}

	sp.client = nil // we connect on demand
	return
}

// 1) Verify signature of classRecords
// 2) Make sure the fingerprint is in authorized_services
// 3) Filter announced actions against authorized actions
func (sp *serviceProxy) Validate() (err error) {
	_, err = sp.validateSignature()
	if err != nil {
		return
	}

	// See if we have this fingerprint in our authorized_services
	// TODO

	return
}

func (sp *serviceProxy) validateSignature() (hexSha1 string, err error) {
	decoded, _ := pem.Decode(sp.rawCert)
	if decoded == nil {
		err = fmt.Errorf("could not find valid cert in `%s`", sp.rawCert)
		return
	}

	// Put pem in form useful for fingerprinting
	cert, err := x509.ParseCertificate(decoded.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse certificate: `%s`", err)
		return
	}

	pkixInterface := cert.PublicKey
	rsaPubKey, ok := pkixInterface.(*rsa.PublicKey)
	if !ok {
		err = fmt.Errorf("could not cast parsed value to rsa.PublicKey")
		return
	}

	err = verifySHA256(sp.rawClassRecords, rsaPubKey, sp.rawSig, false)
	if err != nil {
		return
	}

	hexSha1 = sha1FingerPrint(cert)
	return
}

// commenting this out because it's returning a client not a connection
// func (sp *ServiceProxy) GetConnection() (client *Client, err error) {
// 	if sp.client != nil {
// 		client = sp.client
// 		return
// 	}

// 	sp.client, err = Dial(sp.connspec)
// 	if err != nil {
// 		return
// 	}

// 	return
// }

func (sp *serviceProxy) MarshalJSON() (b []byte, err error) {
	arr := make([]interface{}, 9)
	arr[0] = &sp.version
	arr[1] = &sp.ident
	arr[2] = &sp.sector
	arr[3] = &sp.weight
	arr[4] = &sp.announceInterval
	arr[5] = &sp.connspec
	arr[6] = &sp.protocols

	// TODO: move this to two MarshalJSON interfaces for `ServiceProxyClass` and `ActionDescription`
	// doing so should remove manual copies and separate concerns
	//
	// Serialize actions in this format:
	// 	["bgdispatcher",["poll","",1],["reboot","",1],["report","",1]]
	classSpecs := make([][]interface{}, len(sp.classes), len(sp.classes))
	for i, class := range sp.classes {
		entry := make([]interface{}, 1+len(class.actions), 1+len(class.actions))
		entry[0] = class.className
		for j, action := range class.actions {
			actions := make([]interface{}, 3, 3)

			actionNameCopy := make([]byte, len(action.actionName))
			copy(actionNameCopy, action.actionName)
			actions[0] = string(actionNameCopy)
			actions[1] = &action.crudTags
			actions[2] = &action.version
			entry[j+1] = &actions
		}

		classSpecs[i] = entry
	}
	arr[7] = &classSpecs
	arr[8] = &sp.timestamp

	return json.Marshal(arr)
}
