package kratos

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"
)

type Tracer struct {
	getConn              int64
	connectStart         int64
	connectDone          int64
	tlsHandshakeStart    int64
	tlsHandshakeDone     int64
	gotConn              int64
	wroteRequest         int64
	gotFirstResponseByte int64

	connReused     bool
	connRemoteAddr net.Addr

	protoErrorsMutex sync.Mutex
	protoErrors      []error
}
type ctxKey int

const (
	ctxKeyTracer ctxKey = iota
)

func WithTracer(ctx context.Context, tracer *Tracer) context.Context {
	ctx = httptrace.WithClientTrace(ctx, tracer.Trace())
	ctx = context.WithValue(ctx, ctxKeyTracer, tracer)
	return ctx
}

func (t *Tracer) Trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn:              t.GetConn,
		ConnectStart:         t.ConnectStart,
		ConnectDone:          t.ConnectDone,
		TLSHandshakeStart:    t.TLSHandshakeStart,
		TLSHandshakeDone:     t.TLSHandshakeDone,
		GotConn:              t.GotConn,
		WroteRequest:         t.WroteRequest,
		GotFirstResponseByte: t.GotFirstResponseByte,
	}
}
func now() int64 {
	return time.Now().UnixNano()
}
func (t *Tracer) addError(err error) {
	t.protoErrorsMutex.Lock()
	defer t.protoErrorsMutex.Unlock()
	t.protoErrors = append(t.protoErrors, err)
}

func (t *Tracer) GetConn(hostPort string) {
	t.getConn = now()
}

func (t *Tracer) ConnectStart(network, addr string) {
	// If using dual-stack dialing, it's possible to get this
	// multiple times, so the atomic compareAndSwap ensures
	// that only the first call's time is recorded
	atomic.CompareAndSwapInt64(&t.connectStart, 0, now())
}

func (t *Tracer) ConnectDone(network, addr string, err error) {
	// If using dual-stack dialing, it's possible to get this
	// multiple times, so the atomic compareAndSwap ensures
	// that only the first call's time is recorded
	atomic.CompareAndSwapInt64(&t.connectDone, 0, now())

	if err != nil {
		t.addError(err)
	}
}

func (t *Tracer) TLSHandshakeStart() {
	atomic.CompareAndSwapInt64(&t.tlsHandshakeStart, 0, now())
}

func (t *Tracer) TLSHandshakeDone(state tls.ConnectionState, err error) {
	atomic.CompareAndSwapInt64(&t.tlsHandshakeDone, 0, now())

	if err != nil {
		t.addError(err)
	}
}

func (t *Tracer) GotConn(info httptrace.GotConnInfo) {
	now := now()

	// This shouldn't be called multiple times so no synchronization here,
	// it's better for the race detector to panic if we're wrong.
	t.gotConn = now
	t.connReused = info.Reused
	t.connRemoteAddr = info.Conn.RemoteAddr()

	if t.connReused {
		atomic.CompareAndSwapInt64(&t.connectStart, 0, now)
		atomic.CompareAndSwapInt64(&t.connectDone, 0, now)
	}
}

func (t *Tracer) WroteRequest(info httptrace.WroteRequestInfo) {
	atomic.StoreInt64(&t.wroteRequest, now())

	if info.Err != nil {
		t.addError(info.Err)
	}
}

func (t *Tracer) GotFirstResponseByte() {
	atomic.CompareAndSwapInt64(&t.gotFirstResponseByte, 0, now())
}

type Trail struct {
	StartTime time.Time
	EndTime   time.Time

	// Total connect time (Connecting + TLSHandshaking)
	ConnDuration time.Duration

	// Total request duration, excluding DNS lookup and connect time.
	Duration time.Duration

	Blocked        time.Duration // Waiting to acquire a connection.
	Connecting     time.Duration // Connecting to remote host.
	TLSHandshaking time.Duration // Executing TLS handshake.
	Sending        time.Duration // Writing request.
	Waiting        time.Duration // Waiting for first byte.
	Receiving      time.Duration // Receiving response.

	// Detailed connection information.
	ConnReused     bool
	ConnRemoteAddr net.Addr
	Errors         []error
}

func (t *Tracer) Done() *Trail {
	done := time.Now()

	trail := Trail{
		ConnReused:     t.connReused,
		ConnRemoteAddr: t.connRemoteAddr,
	}

	if t.gotConn != 0 && t.getConn != 0 {
		trail.Blocked = time.Duration(t.gotConn - t.getConn)
	}

	// It's possible for some of the methods of httptrace.ClientTrace to
	// actually be called after the http.Client or http.RoundTripper have
	// already returned our result and we've called Done(). This happens
	// mostly for cancelled requests, but we have to use atomics here as
	// well (or use global Tracer locking) so we can avoid data races.
	connectStart := atomic.LoadInt64(&t.connectStart)
	connectDone := atomic.LoadInt64(&t.connectDone)
	tlsHandshakeStart := atomic.LoadInt64(&t.tlsHandshakeStart)
	tlsHandshakeDone := atomic.LoadInt64(&t.tlsHandshakeDone)
	wroteRequest := atomic.LoadInt64(&t.wroteRequest)
	gotFirstResponseByte := atomic.LoadInt64(&t.gotFirstResponseByte)

	if connectDone != 0 && connectStart != 0 {
		trail.Connecting = time.Duration(connectDone - connectStart)
	}
	if tlsHandshakeDone != 0 && tlsHandshakeStart != 0 {
		trail.TLSHandshaking = time.Duration(tlsHandshakeDone - tlsHandshakeStart)
	}
	if wroteRequest != 0 {
		trail.Sending = time.Duration(wroteRequest - connectDone)
		// If the request was sent over TLS, we need to use
		// TLS Handshake Done time to calculate sending duration
		if tlsHandshakeDone != 0 {
			trail.Sending = time.Duration(wroteRequest - tlsHandshakeDone)
		}

		if gotFirstResponseByte != 0 {
			trail.Waiting = time.Duration(gotFirstResponseByte - wroteRequest)
		}
	}
	if gotFirstResponseByte != 0 {
		trail.Receiving = done.Sub(time.Unix(0, gotFirstResponseByte))
	}

	// Calculate total times using adjusted values.
	trail.EndTime = done
	trail.ConnDuration = trail.Connecting + trail.TLSHandshaking
	trail.Duration = trail.Sending + trail.Waiting + trail.Receiving
	trail.StartTime = trail.EndTime.Add(-trail.Duration)

	t.protoErrorsMutex.Lock()
	defer t.protoErrorsMutex.Unlock()
	if len(t.protoErrors) > 0 {
		trail.Errors = append([]error{}, t.protoErrors...)
	}

	return &trail
}
