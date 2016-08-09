package scamp

import (
	"errors"
	"net"
	"crypto/tls"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"bytes"
	"io/ioutil"
	"time"

	"sync"
	"sync/atomic"
)

// Two minute timeout on clients
var msgTimeout = time.Second * 120

type ServiceActionFunc func(*Message, *Client)
type ServiceAction struct {
	callback ServiceActionFunc
	crudTags string
	version  int
}

type Service struct {
	serviceSpec   string
	sector        string
	name          string
	humanName     string

	listener      net.Listener
	listenerIP    net.IP
	listenerPort  int

	actions       map[string]*ServiceAction
	isRunning     bool

	clientsM      sync.Mutex
	clients       []*Client

	// requests      ClientChan

	cert          tls.Certificate
	pemCert       []byte // just a copy of what was read off disk at tls cert load time

	// stats
	statsCloseChan chan bool
	connectionsAccepted uint64
}

func NewService(sector string, serviceSpec string, humanName string) (serv *Service, err error){
	if len(humanName) > 18 {
		err = fmt.Errorf("name `%s` is too long, must be less than 18 bytes", humanName)
		return
	}

	serv = new(Service)
	serv.sector = sector
	serv.serviceSpec = serviceSpec
	serv.humanName = humanName
	serv.generateRandomName()

	serv.actions = make(map[string]*ServiceAction)

	crtPath := defaultConfig.ServiceCertPath(serv.humanName)
	keyPath := defaultConfig.ServiceKeyPath(serv.humanName)

	if crtPath == nil || keyPath == nil {
		err = fmt.Errorf( "could not find valid crt/key pair for service %s (`%s`,`%s`)", serv.humanName, crtPath, keyPath )
		return
	}

	// Load keypair for tls socket library to use
	serv.cert, err = tls.LoadX509KeyPair( string(crtPath), string(keyPath) )
	if err != nil {
		return
	}

	// Load cert in to memory for announce packet writing
	serv.pemCert, err = ioutil.ReadFile(string(crtPath))
	if err != nil {
		return
	}
	serv.pemCert = bytes.TrimSpace(serv.pemCert)

	// Finally, get ready for incoming requests
	err = serv.listen()
	if err != nil {
		return
	}

	serv.statsCloseChan = make(chan bool)
	go PrintStatsLoop(serv, time.Duration(15)*time.Second, serv.statsCloseChan)

	Trace.Printf("done initializing service")

	return
}

// TODO: port discovery and interface/IP discovery should happen here
// important to set values so announce packets are correct
func (serv *Service)listen() (err error) {
	config := &tls.Config{
		Certificates: []tls.Certificate{ serv.cert },
	}

	Info.Printf("starting service on %s", serv.serviceSpec)
	serv.listener,err = tls.Listen("tcp", serv.serviceSpec, config)
	if err != nil {
		return err
	}
	addr := serv.listener.Addr()
	Info.Printf("service now listening to %s", addr.String())

  // TODO: get listenerIP to return 127.0.0.1 or something other than '::'/nil
  // serv.listenerIP = serv.listener.Addr().(*net.TCPAddr).IP
  serv.listenerIP, err = IPForAnnouncePacket()
  Trace.Printf("serv.listenerIP: `%s`", serv.listenerIP)
  serv.listenerIP = net.ParseIP("127.0.0.1")
  Info.Printf("serv.listenerIP(after): %s", serv.listenerIP)
  if err != nil {
  	return
  }

	serv.listenerPort = serv.listener.Addr().(*net.TCPAddr).Port

	return
}
// TODO Register must handle name registration better, currenty appends everything before the last dot "."
//  infornt of all actions
func (serv *Service)Register(name string, callback ServiceActionFunc) (err error) {
	if serv.isRunning {
		err = errors.New("cannot register handlers while server is running")
		return
	}

	serv.actions[name] = &ServiceAction {
		callback: callback,
		version: 1,
	}
    Info.Printf("actions: %+v", serv.actions)
	return
}

func (serv *Service)Run() {

	forLoop:
	for {
		netConn,err := serv.listener.Accept()
		if err != nil {
			Info.Printf("exiting service service Run(): `%s`", err)
			break forLoop
		}
		Trace.Printf("accepted new connection...")

		var tlsConn (*tls.Conn) = (netConn).(*tls.Conn)
		if tlsConn == nil {
			Error.Fatalf("could not create tlsConn")
			break forLoop
		}

		conn := NewConnection(tlsConn,"service")
		client := NewClient(conn)

		serv.clientsM.Lock()
		serv.clients = append(serv.clients, client)
		serv.clientsM.Unlock()

		go serv.Handle(client)

		atomic.AddUint64(&serv.connectionsAccepted, 1)
	}

	Info.Printf("closing all registered objects")

	serv.clientsM.Lock()
	defer serv.clientsM.Unlock()
	for _,client := range serv.clients {
		client.Close()
	}

	serv.statsCloseChan <- true
}

func (serv *Service)Handle(client *Client) {
	var action *ServiceAction

	HandlerLoop:
	for {
		select {
		case msg,ok := <-client.Incoming():
			if !ok {
				break HandlerLoop
			}
			action = serv.actions[msg.Action]

			if action != nil{
				// yay
				action.callback(msg, client)
			} else {
				Error.Printf("do not know how to handle action `%s`", msg.Action)

				reply := NewMessage()
		    reply.SetMessageType(MESSAGE_TYPE_REPLY)
		    reply.SetEnvelope(ENVELOPE_JSON)
		    reply.SetRequestId(msg.RequestId)
		    reply.Write([]byte(`{"error": "no such action"`))
				_,err := client.Send(reply)
				if err != nil {
					client.Close()
					break HandlerLoop
				}

			}
		case <- time.After(msgTimeout):
			Error.Printf("timeout... dying!")
			break HandlerLoop
		}
	}

	client.Close()
	serv.RemoveClient(client)

	Trace.Printf("done handling client")

}

func (serv *Service)RemoveClient(client *Client) (err error){
	serv.clientsM.Lock()
	defer serv.clientsM.Unlock()

	index := -1
	for i,entry := range serv.clients {
		if client == entry {
			index = i
			break
		}
	}

	if index == -1 {
		Error.Printf("tried removing client that wasn't being tracked")
		return fmt.Errorf("unknown client") // TODO can I get the client's IP?
	}

	client.Close()
	serv.clients = append(serv.clients[:index], serv.clients[index+1:]...)

	return nil
}

func (serv *Service)Stop(){
	// Sometimes we Stop() before service after service has been init but before it is started
	// The usual case is a bad config in another plugin
	if serv.listener != nil {
		serv.listener.Close()
	}
}

func (serv *Service)MarshalText() (b []byte, err error){
	var buf bytes.Buffer

	serviceProxy := ServiceAsServiceProxy(serv)
	classRecord,err := json.Marshal(&serviceProxy)
	if err != nil {
		return
	}

	sig, err := SignSHA256(classRecord, serv.cert.PrivateKey.(*rsa.PrivateKey))
	if err != nil {
		return
	}
	sigParts := stringToRows(sig, 76)

	buf.Write(classRecord)
	buf.WriteString("\n\n")
	buf.Write(serv.pemCert)
	buf.WriteString("\n\n")
	// buf.WriteString(sig)
	// buf.WriteString("\n\n")
	for _,part := range sigParts {
		buf.WriteString(part)
		buf.WriteString("\n")
	}
	buf.WriteString("\n")

	b = buf.Bytes()
	return
}

func stringToRows(input string, rowlen int) (output []string) {
	output = make([]string,0)

	if len(input) <= 76 {
		output = append(output, input)
	} else {
		substr := input[:]
		var row string
		var done bool = false
		for {
			if len(substr) > 76 {
				row = substr[0:76]
				substr = substr[76:]
			} else {
				row = substr[:]
				done = true
			}
			output = append(output,row)
			if done {
				break
			}
		}
	}

	return
}

func (serv *Service)generateRandomName() {
	randBytes := make([]byte, 18, 18)
	read,err := rand.Read(randBytes)
	if err != nil {
		err = fmt.Errorf("could not generate all rand bytes needed. only read %d of 18", read)
		return
	}
	base64RandBytes := base64.StdEncoding.EncodeToString(randBytes)

	var buffer bytes.Buffer
	buffer.WriteString(serv.humanName)
	buffer.WriteString("-")
	buffer.WriteString(base64RandBytes[0:])
	serv.name = string(buffer.Bytes())
}
