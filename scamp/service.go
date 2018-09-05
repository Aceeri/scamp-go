package scamp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net"
	"os"
	// "encoding/json"
	"bytes"
	"fmt"
	"time"

	"sync"
	"sync/atomic"
)

var livenessDirPath = "/backplane/running-services/"

// Two minute timeout on clients
var msgTimeout = time.Second * 120

// ServiceActionFunc represents a service callback
type ServiceActionFunc func(*Message, *Client)

// ServiceAction interface
type ServiceAction struct {
	callback ServiceActionFunc
	crudTags string
	version  int
}

// Service represents a scamp service
type Service struct {
	serviceSpec string
	sector      string
	name        string
	humanName   string

	listener     net.Listener
	listenerIP   net.IP
	listenerPort int

	actions   map[string]*ServiceAction
	isRunning bool

	clientsM sync.Mutex
	clients  []*Client

	// requests      ClientChan

	cert    tls.Certificate
	pemCert []byte // just a copy of what was read off disk at tls cert load time

	// stats
	statsCloseChan      chan bool
	connectionsAccepted uint64
}

// NewService intializes and returns pointer to a new scamp service
func NewService(sector string, serviceSpec string, humanName string) (*Service, error) {
	crtPath := DefaultConfig().ServiceCertPath(humanName)
	keyPath := DefaultConfig().ServiceKeyPath(humanName)

	var err error

	if crtPath == nil || keyPath == nil {
		err = fmt.Errorf("could not find valid crt/key pair for service %s (`%s`,`%s`)", humanName, crtPath, keyPath)
		return nil, err
	}

	// Load keypair for tls socket library to use
	keypair, err := tls.LoadX509KeyPair(string(crtPath), string(keyPath))
	if err != nil {
		return nil, err
	}

	// Load certificate as bytes
	pemCert, err := ioutil.ReadFile(string(crtPath))
	if err != nil {
		return nil, err
	}

	return NewServiceExplicitCert(sector, serviceSpec, humanName, keypair, pemCert)
}

// NewServiceExplicitCert intializes and returns pointer to a new scamp service,
// with an explicitly specified certificate rather than an implicitly discovered one.
// keypair is a TLS certificate, and pemCert is the raw bytes of an X509 certificate.
func NewServiceExplicitCert(sector string, serviceSpec string, humanName string, keypair tls.Certificate, pemCert []byte) (serv *Service, err error) {
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

	serv.cert = keypair

	// Load cert in to memory for announce packet writing
	serv.pemCert = bytes.TrimSpace(pemCert)

	// Finally, get ready for incoming requests
	err = serv.listen()
	if err != nil {
		return
	}

	serv.statsCloseChan = make(chan bool)
	// go PrintStatsLoop(serv, time.Duration(15)*time.Second, serv.statsCloseChan)

	// Trace.Printf("done initializing service")
	return
}

// TODO: port discovery and interface/IP discovery should happen here
// important to set values so announce packets are correct
func (serv *Service) listen() (err error) {
	config := &tls.Config{
		Certificates: []tls.Certificate{serv.cert},
	}

	Info.Printf("starting service on %s", serv.serviceSpec)
	serv.listener, err = tls.Listen("tcp", serv.serviceSpec, config)
	if err != nil {
		return err
	}
	addr := serv.listener.Addr()
	Info.Printf("service now listening to %s", addr.String())

	// TODO: get listenerIP to return 127.0.0.1 or something other than '::'/nil
	// serv.listenerIP = serv.listener.Addr().(*net.TCPAddr).IP
	serv.listenerIP, err = getIPForAnnouncePacket()
	// Trace.Printf("serv.listenerIP: `%s`", serv.listenerIP)

	if err != nil {
		return
	}

	serv.listenerPort = serv.listener.Addr().(*net.TCPAddr).Port

	return
}

// Register registers a service handler callback
func (serv *Service) Register(name string, callback ServiceActionFunc) (err error) {
	if serv.isRunning {
		err = errors.New("cannot register handlers while server is running")
		return
	}

	serv.actions[name] = &ServiceAction{
		callback: callback,
		version:  1,
	}
	return
}

//Run starts a scamp service
func (serv *Service) Run() {
	err := serv.createKubeLivenessFile()
	if err != nil {
		fmt.Println(err)
	}

forLoop:
	for {
		netConn, err := serv.listener.Accept()
		if err != nil {
			// Info.Printf("exiting service Run(): `%s`", err)
			break forLoop
		}
		// Trace.Printf("accepted new connection...")

		//var tlsConn (*tls.Conn) = (netConn).(*tls.Conn)
		tlsConn := (netConn).(*tls.Conn)
		if tlsConn == nil {
			Error.Fatalf("could not create tlsConn")
			break forLoop
		}

		conn := NewConnection(tlsConn, "service")
		client := NewClient(conn, "service")

		serv.clientsM.Lock()
		serv.clients = append(serv.clients, client)
		serv.clientsM.Unlock()

		go serv.Handle(client)

		atomic.AddUint64(&serv.connectionsAccepted, 1)
	}

	// Info.Printf("closing all registered objects")

	serv.clientsM.Lock()
	for _, client := range serv.clients {
		client.Close()
	}
	serv.clientsM.Unlock()

	serv.statsCloseChan <- true
}

//Handle handles incoming client messages received via the cient MessageChan
func (serv *Service) Handle(client *Client) {
	var action *ServiceAction
	//Info.Printf("handling client for remote connection: %s\n", client.conn.conn.RemoteAddr())
HandlerLoop:
	for {
		select {
		case msg, ok := <-client.Incoming():
			if !ok {
				break HandlerLoop
			}
			action = serv.actions[msg.Action]

			if action != nil {
				// Info.Printf("handling action %s\n", action.crudTags)
				action.callback(msg, client)
			} else {
				Error.Printf("do not know how to handle action `%s`", msg.Action)

				reply := NewMessage()
				reply.SetMessageType(MessageTypeReply)
				reply.SetEnvelope(EnvelopeJSON)
				reply.SetRequestID(msg.RequestID)
				reply.Write([]byte(`{"error": "no such action"}`))
				_, err := client.Send(reply)
				if err != nil {
					client.Close()
					break HandlerLoop
				}
			}
		case <-time.After(msgTimeout):
			break HandlerLoop
		}
	}

	client.Close()
	serv.RemoveClient(client)
}

// RemoveClient removes a client from the scamp service
func (serv *Service) RemoveClient(client *Client) (err error) {
	serv.clientsM.Lock()
	defer serv.clientsM.Unlock()

	index := -1
	for i, entry := range serv.clients {
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

// Stop closes the service's net.Listener
func (serv *Service) Stop() {
	after := time.After(30 * time.Second)

ServiceWait:
	for {
		select {
		case <-after:
			break ServiceWait
		default:
		}

		serv.clientsM.Lock()
		clientsLength := len(serv.clients)
		serv.clientsM.Unlock()

		if clientsLength == 0 {
			break
		}
	}

	if serv.listener != nil {
		serv.listener.Close()
	}
	fmt.Println("shutting down")
	err := serv.removeKubeLivenessFile()
	if err != nil {
		fmt.Println("could not remove liveness file: ", err)
	}
	fmt.Println("shutdown done")
}

// MarshalText serializes a scamp service
func (serv *Service) MarshalText() (b []byte, err error) {
	var buf bytes.Buffer

	serviceProxy := serviceAsServiceProxy(serv)

	classRecord, err := serviceProxy.MarshalJSON() //json.Marshal(&serviceProxy) //Marshal is mangling service actions
	if err != nil {
		return
	}
	sig, err := signSHA256(classRecord, serv.cert.PrivateKey.(*rsa.PrivateKey))
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
	for _, part := range sigParts {
		buf.WriteString(part)
		buf.WriteString("\n")
	}
	buf.WriteString("\n")

	b = buf.Bytes()
	return
}

func stringToRows(input string, rowlen int) (output []string) {
	output = make([]string, 0)

	if len(input) <= 76 {
		output = append(output, input)
	} else {
		substr := input[:]
		var row string
		done := false
		for {
			if len(substr) > 76 {
				row = substr[0:76]
				substr = substr[76:]
			} else {
				row = substr[:]
				done = true
			}
			output = append(output, row)
			if done {
				break
			}
		}
	}

	return
}

func (serv *Service) generateRandomName() {
	randBytes := make([]byte, 18, 18)
	read, err := rand.Read(randBytes)
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

// TODO: we should dicuss movng the path to the liveness file to a config file (like soa.conf) or having it declared
// when creating the service
func (serv *Service) createKubeLivenessFile() error {

	if _, err := os.Stat(livenessDirPath); os.IsNotExist(err) {
		err = os.MkdirAll(livenessDirPath, 0755)
		if err != nil {
			return err
		}
	}

	file, err := os.Create(livenessDirPath + serv.humanName)
	if err != nil {
		return err
	}
	defer file.Close()
	return nil
}

func (serv *Service) removeKubeLivenessFile() error {
	path := livenessDirPath + serv.humanName
	err := os.Remove(path)
	if err != nil {
		return err
	}
	return nil
}
