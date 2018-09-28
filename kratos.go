package kratos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Comcast/webpa-common/device"
	"github.com/Comcast/webpa-common/logging"
	"github.com/Comcast/webpa-common/wrp"
	"github.com/go-kit/kit/log"
	"github.com/gorilla/websocket"
)

//go:generate stringer -type=Event
type Event int

const (
	Error Event = iota + 1
	Open
	Ping
	Pong
	Close
	Message
	Done
)

const (
	// Time allowed to write a message to the peer.
	writeWait = time.Duration(10) * time.Second

	// Time allowed to wait in between pings
	pingWait = time.Duration(60) * time.Second
)

type EventHandler func(args ...interface{}) error

// ClientFactory is used to generate a client by calling new on this type
type ClientFactory struct {
	DeviceName     string
	FirmwareName   string
	ModelName      string
	Manufacturer   string
	DestinationURL string
	Handlers       []HandlerRegistry
	HandlePingMiss HandlePingMiss
	ClientLogger   log.Logger

	UseTracer     bool
	EventHandlers map[Event][]EventHandler
}

// New is used to create a new kratos Client from a ClientFactory
func (f *ClientFactory) New() (Client, error) {
	return f.NewWithContext(context.Background())
}

func (f *ClientFactory) NewWithContext(ctx context.Context) (Client, error) {
	inHeader := &clientHeader{
		deviceName:   f.DeviceName,
		firmwareName: f.FirmwareName,
		modelName:    f.ModelName,
		manufacturer: f.Manufacturer,
	}

	tracer := &Tracer{}
	newConnection, connectionURL, err := createConnection(inHeader, f.DestinationURL, tracer)

	if err != nil {
		return nil, err
	}

	// at this point we know that the URL connection is legitimate, so we can do some string manipulation
	// with the knowledge that `:` will be found in the string twice
	connectionURL = connectionURL[len("ws://"):strings.LastIndex(connectionURL, ":")]

	newClient := &client{
		deviceID:        inHeader.deviceName,
		userAgent:       "WebPA-1.6(" + inHeader.firmwareName + ";" + inHeader.modelName + "/" + inHeader.manufacturer + ";)",
		deviceProtocols: "TODO-what-to-put-here",
		hostname:        connectionURL,
		handlers:        f.Handlers,
		connection:      newConnection,
		headerInfo:      inHeader,

		done:          make(chan struct{}),
		eventHandlers: f.EventHandlers,
		tracer:        tracer,
	}

	myPingMissHandler := pingMissHandler{
		handlePingMiss: f.HandlePingMiss,
	}

	if f.ClientLogger != nil {
		newClient.Logger = f.ClientLogger
		myPingMissHandler.Logger = f.ClientLogger
	} else {
		newClient.Logger = logging.DefaultLogger()
		myPingMissHandler.Logger = logging.DefaultLogger()
	}

	for i := range newClient.handlers {
		newClient.handlers[i].keyRegex, err = regexp.Compile(newClient.handlers[i].HandlerKey)
		if err != nil {
			return nil, err
		}
	}
	pinged := make(chan string)
	pingTimer := time.NewTimer(pingWait)

	// Pass ping/pong events through the main control loop
	pingChan := make(chan string)
	pongChan := make(chan string)
	newConnection.SetPingHandler(func(msg string) error { pinged <- msg; pingChan <- msg; return nil })
	newConnection.SetPongHandler(func(pingID string) error { pongChan <- pingID; return nil })

	readDataChan := make(chan *wrp.Message)
	readCloseChan := make(chan int)
	readErrChan := make(chan error)

	go myPingMissHandler.checkPing(pingTimer, pinged, newClient)
	go newClient.readPump(readDataChan, readErrChan, readCloseChan)
	go newClient.controlLoop(pingChan, pongChan, readDataChan, readErrChan, readCloseChan, ctx)

	return newClient, nil
}

// HandlePingMiss is a function called when we run into situations where we're not getting anymore pings
// the implementation of this function needs to be handled by the user of kratos
type HandlePingMiss func() error

type pingMissHandler struct {
	handlePingMiss HandlePingMiss
	log.Logger
}

func (pmh *pingMissHandler) checkPing(inTimer *time.Timer, pinged <-chan string, inClient Client) {
	defer inClient.Close()
	pingMiss := false

	for !pingMiss {
		select {
		case <-inTimer.C:
			logging.Info(pmh).Log(logging.MessageKey(), "Ping miss, calling handler and closing client!")
			pingMiss = true
			err := pmh.handlePingMiss()
			if err != nil {
				logging.Info(pmh).Log(logging.MessageKey(), "Error handling ping miss:", logging.ErrorKey(), err)
			}
		case <-pinged:
			if !inTimer.Stop() {
				<-inTimer.C
			}
			inTimer.Reset(pingWait)
		}
	}
}

// Client is what function calls we expose to the user of kratos
type Client interface {
	Hostname() string
	OnEvent(event Event, handler EventHandler)
	Send(message interface{}) error
	Close() error
	SetTrailCallback(TrailCallback)
}

type websocketConnection interface {
	WriteMessage(messageType int, data []byte) error
	WriteControl(messageType int, data []byte, deadline time.Time) error
	ReadMessage() (messageType int, p []byte, err error)
	Close() error
}

// ReadHandler should be implemented by the user so that they
// may deal with received messages how they please
type ReadHandler interface {
	HandleMessage(msg interface{})
}

// HandlerRegistry is an internal data type for Client interface
// that helps keep track of registered handler functions
type HandlerRegistry struct {
	HandlerKey string
	keyRegex   *regexp.Regexp
	Handler    ReadHandler
}

type TrailCallback func(*Trail)

type TrailTrace interface {
	SetTrailCallback(TrailCallback)
}

type client struct {
	deviceID        string
	userAgent       string
	deviceProtocols string
	hostname        string
	handlers        []HandlerRegistry
	connection      websocketConnection
	headerInfo      *clientHeader
	log.Logger

	eventHandlers map[Event][]EventHandler
	shutdownOnce  sync.Once
	done          chan struct{}

	tracer        *Tracer
	trailCallBack TrailCallback
}

// used to track everything that we want to know about the client headers
type clientHeader struct {
	deviceName   string
	firmwareName string
	modelName    string
	manufacturer string
}

func (c *client) controlLoop(pingChan <-chan string,
	pongChan <-chan string,
	readDataChan <-chan *wrp.Message,
	readErrChan <-chan error,
	readCloseChan <-chan int,
	ctx context.Context) error {
	var err error
	for {
		select {
		case pingData := <-pingChan:
			// Handle pings received from the server
			// - trigger the `ping` event
			// - reply with pong (needed when `SetPingHandler` is overwritten)
			err := c.connection.WriteControl(websocket.PongMessage, []byte(pingData), time.Now().Add(writeWait))
			if err != nil {
				c.handleEvent(Error, err)
			}
			c.handleEvent(Ping)
		case pongData := <-pongChan:
			c.handleEvent(Pong, pongData)
		case wrpData := <-readDataChan:
			for i := 0; i < len(c.handlers); i++ {
				if c.handlers[i].keyRegex.MatchString(wrpData.Destination) {
					c.handlers[i].Handler.HandleMessage(*wrpData)
				}
			}
			c.handleEvent(Message, wrpData)
		case readErr := <-readErrChan:
			c.handleEvent(Error, readErr)
		case readClose := <-readCloseChan:
			c.handleEvent(Close, readClose)
		case <-ctx.Done():
			err = c.Close()
		case <-c.done:
			c.handleEvent(Done)
			return err
		}
	}
}

func (c *client) handleEvent(event Event, args ...interface{}) {
	if handlers, ok := c.eventHandlers[event]; ok {
		for _, handler := range handlers {
			if err := handler(args...); err != nil {
				c.Log(logging.MessageKey(), "Unhandled Error", "err", err)
			}
		}
	}
}

func (c *client) OnEvent(event Event, handler EventHandler) {
	if handlers, ok := c.eventHandlers[event]; ok {
		c.eventHandlers[event] = append(handlers, handler)
	} else {
		c.eventHandlers[event] = []EventHandler{handler}
	}
}

func (c *client) Hostname() string {
	return c.hostname
}

// used to open a channel for writing to servers
func (c *client) Send(message interface{}) (err error) {
	logging.Info(c).Log(logging.MessageKey(), "Sending message...")

	var buffer bytes.Buffer

	if err = wrp.NewEncoder(&buffer, wrp.Msgpack).Encode(message); err == nil {
		err = c.connection.WriteMessage(websocket.BinaryMessage, buffer.Bytes())
	}
	if err != nil {
		c.handleEvent(Error, err)
	}
	return
}

// will close the connection to the server
func (c *client) Close() (err error) {
	logging.Info(c).Log("Closing client...")

	c.shutdownOnce.Do(func() {
		// trigger `close` event when the client closes the connection
		c.handleEvent(Close)
		err = c.connection.Close()

		// Stops the main control loop
		close(c.done)
		if c.trailCallBack != nil {
			c.trailCallBack(c.tracer.Done())
		}
	})
	return
}

func (c *client) SetTrailCallback(trailCallback TrailCallback) {
	c.trailCallBack = trailCallback
}

func (c *client) read(readChan chan *wrp.Message, errorChan chan error, closeChan chan int) (err error) {
	var serverMessage []byte
	_, serverMessage, err = c.connection.ReadMessage()
	if err != nil {
		if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
			closeChan <- err.(*websocket.CloseError).Code
		} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
			// Emit the error if it is not CloseNormalClosure
			// and the error is not  originated from closing the socket ourselves with `CloseGoingAway`
			errorChan <- err
		}

		//CloseGoingAway errors are ignored
		return
	}

	// decode the message so we can read it
	wrpData := wrp.Message{}
	err = wrp.NewDecoderBytes(serverMessage, wrp.Msgpack).Decode(&wrpData)

	if err != nil {
		return
	}
	readChan <- &wrpData
	return
}

// going to be used to access the HandleMessage() function
func (c *client) readPump(readChan chan *wrp.Message, errorChan chan error, closeChan chan int) (err error) {
	logging.Info(c).Log(logging.MessageKey(), "Reading message...")
	defer func() {
		er := c.connection.Close()
		logging.Warn(c).Log(logging.MessageKey(), "Stopped reading messages", "err", er)
	}()

	for {
		err = c.read(readChan, errorChan, closeChan)
		if err != nil {
			return err
		}
	}
	return nil
}

// private func used to generate the client that we're looking to produce
func createConnection(headerInfo *clientHeader, httpURL string, tracer *Tracer) (connection *websocket.Conn, wsURL string, err error) {
	_, err = device.ParseID(headerInfo.deviceName)

	if err != nil {
		return nil, "", err
	}

	// make a header and put some data in that (including MAC address)
	// TODO: find special function for user agent
	headers := make(http.Header)
	headers.Add("X-Webpa-Device-Name", headerInfo.deviceName)
	headers.Add("X-Webpa-Firmware-Name", headerInfo.firmwareName)
	headers.Add("X-Webpa-Model-Name", headerInfo.modelName)
	headers.Add("X-Webpa-Manufacturer", headerInfo.manufacturer)

	//make sure destUrl's protocol is websocket (ws)
	wsURL = strings.Replace(httpURL, "http", "ws", 1)

	// creates a new client connection given the URL string
	connection, resp, err := websocket.DefaultDialer.DialContext(WithTracer(context.Background(), tracer), wsURL, headers)
	if err == websocket.ErrBadHandshake && resp.StatusCode == http.StatusTemporaryRedirect {
		//Get url to which we are redirected and reconfigure it
		wsURL = strings.Replace(resp.Header.Get("Location"), "http", "ws", 1)

		connection, resp, err = websocket.DefaultDialer.Dial(wsURL, headers)
	}

	if err != nil {
		if resp != nil {
			err = createError(resp, err)
		}
		return nil, "", err
	}

	return connection, wsURL, nil
}

type ResponseMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (msg ResponseMessage) String() string {
	return fmt.Sprintf("%d:%s", msg.Code, msg.Message)
}

type ResponseError struct {
	Message  ResponseMessage
	SubError error
}

func createError(resp *http.Response, err error) *ResponseError {
	var msg ResponseMessage
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(data, &msg)

	if msg.Message == "" {
		switch resp.StatusCode {
		case device.StatusDeviceDisconnected:
			msg.Message = "ErrorDeviceBusy"
		case device.StatusDeviceTimeout:
			msg.Message = "ErrorTransactionsClosed/ErrorTransactionsAlreadyClosed/ErrorDeviceClosed"
		default:
			msg.Message = http.StatusText(msg.Code)
		}
	}

	return &ResponseError{
		Message:  msg,
		SubError: err,
	}
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("message: %s with error: %s", e.Message, e.SubError.Error())
}
