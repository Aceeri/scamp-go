package scamp

import (
	"sync"
)

// type ClientChan chan *Client

// Client represents a scamp client
type Client struct {
	conn            *Connection
	serv            *Service
	requests        chan *Message
	openReplies     map[int]chan *Message
	openRepliesLock sync.Mutex
	isClosed        bool
	closedM         sync.Mutex
	sendM           sync.Mutex
	nextRequestID   int
	spIdent         string
}

// Dial calls DialConnection to establish a secure (tls) connection,
// and uses that connection to create a client
func Dial(connspec string) (client *Client, err error) {
	// Trace.Printf("Connecting to: `%s`", connspec)

	conn, err := DialConnection(connspec)
	if err != nil {
		return
	}
	client = NewClient(conn, "service-proxy")

	return
}

// NewClient takes a scamp connection and creates a new scamp client
func NewClient(conn *Connection, clientType string) (client *Client) {
	// Trace.Printf("client allocated")

	client = new(Client)
	client.conn = conn
	client.requests = make(chan *Message)
	client.openReplies = make(map[int]chan *Message)
	// clientID++
	// client.ID = clientID
	// if len(clientType) > 0 {
	// 	Warning.Printf("client %v created for %s\n", client.ID, clientType)
	// } else {
	// 	Warning.Printf("client %v created\n", client.ID)
	// }
	conn.SetClient(client)

	// grNum++
	// go client.splitReqsAndReps(grNum, clientID)
	go client.splitReqsAndReps()

	return
}

// SetService assigns a *Service to client.serv
func (client *Client) SetService(serv *Service) {
	client.serv = serv
}

// Send TODO: would be nice to have different code path for scamp responses
// so that we don't need to rely on garbage collection of channels
// when we're replying and don't expect or need a response
func (client *Client) Send(msg *Message) (responseChan chan *Message, err error) {
	client.sendM.Lock()
	defer client.sendM.Unlock()

	client.nextRequestID++
	msg.RequestID = client.nextRequestID
	err = client.conn.Send(msg)
	if err != nil {
		// Trace.Printf("SCAMP send error: %s", err)
		return
	}

	if msg.MessageType == MessageTypeRequest {
		// Trace.Printf("sending request so waiting for reply")
		responseChan = make(chan *Message)
		client.openRepliesLock.Lock()
		client.openReplies[msg.RequestID] = responseChan
		client.openRepliesLock.Unlock()
	} else {
		// Trace.Printf("sending reply so done with this message")
	}

	return
}

// Close unlocks a client mutex and closes the connection
func (client *Client) Close() {
	if len(client.spIdent) > 0 {
		sp := DefaultCache.Retrieve(client.spIdent)
		if sp != nil {
			sp.client = nil
		}
	}

	client.closedM.Lock()
	defer client.closedM.Unlock()
	if client.isClosed {
		// Trace.Printf("client already closed. skipping shutdown.")
		return
	}

	// Trace.Printf("closing client...")
	// Trace.Printf("closing client conn...")
	client.closeConnection(client.conn)

	// Notify wrapper service that we're dead
	if client.serv != nil {
		// Trace.Printf("removing client from service...")
		client.serv.RemoveClient(client)
	}

	// Trace.Printf("marking client as closed...")
	client.isClosed = true
}

// closeConnection calls client.conn.Close() and sets the client.conn to nil
func (client *Client) closeConnection(conn *Connection) {
	if !client.conn.isClosed {
		client.conn.Close()
	}
	client.conn = nil
}

//func (client *Client) splitReqsAndReps(grNum, clientID int) (err error) {
func (client *Client) splitReqsAndReps() (err error) {
	var replyChan chan *Message

forLoop:
	for {
		// Trace.Printf("Entering forLoop splitReqsAndReps")
		select {
		case message, ok := <-client.conn.msgs:
			if !ok {
				// Trace.Printf("client.conn.msgs... CLOSED!")
				break forLoop
			}
			if message == nil {
				continue
			}

			// Trace.Printf("Splitting incoming message to reqs and reps")

			if message.MessageType == MessageTypeRequest {
				// interesting things happen if there are outstanding messages
				// and the client closes
				client.requests <- message
			} else if message.MessageType == MessageTypeReply {
				client.openRepliesLock.Lock()
				replyChan = client.openReplies[message.RequestID]
				if replyChan == nil {
					// Error.Printf("got an unexpected reply for requestId: %d. Skipping.", message.RequestID)
					client.openRepliesLock.Unlock()
					continue
				}

				delete(client.openReplies, message.RequestID)
				client.openRepliesLock.Unlock()

				replyChan <- message
			} else {
				// Trace.Printf("Could not handle msg, it's neither req or reply. Skipping.")
				continue
			}
		}
	}

	// Trace.Printf("done with SplitReqsAndReps")
	close(client.requests)
	client.openRepliesLock.Lock()
	for _, openReplyChan := range client.openReplies {
		close(openReplyChan)
	}
	client.openRepliesLock.Unlock()
	if !client.isClosed {
		client.Close()
	}

	return
}

// Incoming returns a client's MessageChan
func (client *Client) Incoming() chan *Message {
	return client.requests
}
