package serverGo

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
)

var errTooLarge = errors.New("http: request too large")

type closeWriter interface {
	CloseWrite() error
}

type badRequestError string

func (e badRequestError) Error() string { return "Bad Request: " + string(e) }

type readResult struct {
	n   int
	err error
	b   byte // byte read, if n == 1
}

// connReader is the io.Reader wrapper used by *conn. It combines a
// selectively-activated io.LimitedReader (to bound request header
// read sizes) with support for selectively keeping an io.Reader.Read
// call blocked in a background goroutine to wait for activity and
// trigger a CloseNotifier channel.
type connReader struct {
	r      io.Reader
	remain int64 // bytes remaining
}

func (cr *connReader) setReadLimit(remain int64) { cr.remain = remain }

// maxInt64 is the effective "infinite" value for the Server and
// Transport's byte-limiting readers.
const maxInt64 = 1<<63 - 1

// 设置成无穷
func (cr *connReader) setInfiniteReadLimit() { cr.remain = maxInt64 }
func (cr *connReader) hitReadLimit() bool    { return cr.remain <= 0 }
func (cr *connReader) Read(p []byte) (n int, err error) {
	if cr.hitReadLimit() {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return
	}
	if int64(len(p)) > cr.remain {
		p = p[:cr.remain]
	}

	n, err = cr.r.Read(p)
	cr.remain -= int64(n)
	return
}

// checkConnErrorWriter writes to c.rwc and records any write errors to c.werr.
// It only contains one field (and a pointer field at that), so it
// fits in an interface value without an extra allocation.
type checkConnErrorWriter struct {
	c *conn
}

func (w checkConnErrorWriter) Write(p []byte) (n int, err error) {
	n, err = w.c.rwc.Write(p)
	if err != nil && w.c.werr == nil {
		w.c.werr = err
	}
	return
}

// http请求
type conn struct {
	// 服务
	server *Server

	// rwc is the underlying network connection.
	// This is never wrapped by other types and is the value given out
	// to CloseNotifier callers. It is usually of type *net.TCPConn or
	// *tls.Conn.
	// 真正的tcp连接
	rwc net.Conn

	// remoteAddr is rwc.RemoteAddr().String(). It is not populated synchronously
	// inside the Listener's Accept goroutine, as some implementations block.
	// It is populated immediately inside the (*conn).serve goroutine.
	// This is the value of a Handler's (*Request).RemoteAddr.
	remoteAddr string

	// werr is set to the first write error to rwc.
	// It is set via checkConnErrorWriter{w}, where bufw writes.
	werr error

	// r is bufr's read source. It's a wrapper around rwc that provides
	// io.LimitedReader-style limiting (while reading request headers)
	// and functionality to support CloseNotifier. See *connReader docs.
	r *connReader

	// bufr reads from r.
	// Users of bufr must hold mu.
	bufr *bufio.Reader

	// bufw writes to checkConnErrorWriter{c}, which populates werr on error.
	bufw *bufio.Writer

	// lastMethod is the method of the most recent request
	// on this connection, if any.
	lastMethod string

	// mu guards hijackedv, use of bufr, (*response).closeNotifyCh.
	mu sync.Mutex
}

// Close the connection.
func (c *conn) close() {
	c.finalFlush()
	c.rwc.Close()
}

// 开启一个新的连接
func (c *conn) serve(ctx context.Context) {
	c.remoteAddr = c.rwc.RemoteAddr().String()
	// 输出错误日志
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			c.server.logf("http: panic serving %v: %v\n%s", c.remoteAddr, err, buf)
		}
		c.close()
	}()

	// 初始化tcp接口
	c.r = &connReader{r: c.rwc}
	// 初始化数据存储buffer
	c.bufr = newBufioReader(c.r)
	// 初始化错误信息buffer
	c.bufw = newBufioWriterSize(checkConnErrorWriter{c}, 4<<10)

	ctx, cancelCtx := context.WithCancel(ctx)
	defer cancelCtx()

	// 长连接, 所以是for循环
	for {
		// 解析请求, 返回response
		w, err := c.readRequest(ctx)
		// TODO
		if err != nil {
			if err == errTooLarge {
				io.WriteString(c.rwc, "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large")
				c.closeWriteAndWait()
				return
			}
			if err == io.EOF {
				return // don't reply
			}
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				return // don't reply
			}
			var publicErr string
			if v, ok := err.(badRequestError); ok {
				publicErr = ": " + string(v)
			}
			io.WriteString(c.rwc, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n400 Bad Request"+publicErr)
			return
		}

		// 调用路由函数处理请求
		serverHandler{c.server}.ServeHTTP(w, w.req)
		w.cancelCtx()

		// 关闭连接,不再接收请求
		w.finishRequest()
		if !w.shouldReuseConnection() {
			if w.requestBodyLimitHit || w.closedRequestBodyEarly() {
				c.closeWriteAndWait()
			}
			return
		}
	}
}

// This should be >= 512 bytes for DetectContentType,
// but otherwise it's somewhat arbitrary.
const bufferBeforeChunkingSize = 2048

// 解析请求数据, 返回response
func (c *conn) readRequest(ctx context.Context) (w *response, err error) {

	c.r.setReadLimit(c.server.initialReadLimitSize())
	c.mu.Lock() // while using bufr
	if c.lastMethod == "POST" {
		// RFC 2616 section 4.1 tolerance for old buggy clients.
		peek, _ := c.bufr.Peek(4) // ReadRequest will get err below
		c.bufr.Discard(numLeadingCRorLF(peek))
	}

	// 返回request
	req, err := readRequest(c.bufr)
	c.mu.Unlock()
	if err != nil {
		if c.r.hitReadLimit() {
			return nil, errTooLarge
		}
		return nil, err
	}

	// 检查协议版本号是否为1开头
	if req.ProtoMajor != 1 {
		return nil, badRequestError("unsupported protocol version")
	}

	c.lastMethod = req.Method
	c.r.setInfiniteReadLimit()

	hosts, haveHost := req.Header["Host"]
	// 检查协议号最小值
	if req.ProtoAtLeast(1, 1) && (!haveHost || len(hosts) == 0) {
		return nil, badRequestError("missing required Host header")
	}
	if len(hosts) > 1 {
		return nil, badRequestError("too many Host headers")
	}
	if len(hosts) == 1 && !ValidHostHeader(hosts[0]) {
		return nil, badRequestError("malformed Host header")
	}
	// 检查请求头
	for k, vv := range req.Header {
		if !ValidHeaderFieldName(k) {
			return nil, badRequestError("invalid header name")
		}
		for _, v := range vv {
			if !ValidHeaderFieldValue(v) {
				return nil, badRequestError("invalid header value")
			}
		}
	}
	delete(req.Header, "Host")

	ctx, cancelCtx := context.WithCancel(ctx)
	req.ctx = ctx
	req.RemoteAddr = c.remoteAddr

	if body, ok := req.Body.(*body); ok {
		body.doEarlyClose = true
	}

	// response
	w = &response{
		conn:          c,
		cancelCtx:     cancelCtx,
		req:           req,
		reqBody:       req.Body,
		handlerHeader: make(Header),
		contentLength: -1,

		wantsClose: req.wantsClose(),
	}
	w.cw.res = w
	w.w = newBufioWriterSize(&w.cw, bufferBeforeChunkingSize)
	return w, nil
}

// rstAvoidanceDelay is the amount of time we sleep after closing the
// write side of a TCP connection before closing the entire socket.
// By sleeping, we increase the chances that the client sees our FIN
// and processes its final data before they process the subsequent RST
// from closing a connection with known unread data.
// This RST seems to occur mostly on BSD systems. (And Windows?)
// This timeout is somewhat arbitrary (~latency around the planet).
const rstAvoidanceDelay = 500 * time.Millisecond

// closeWrite flushes any outstanding data and sends a FIN packet (if
// client is connected via TCP), signalling that we're done. We then
// pause for a bit, hoping the client processes it before any
// subsequent RST.
//
// See https://golang.org/issue/3595
func (c *conn) closeWriteAndWait() {
	c.finalFlush()
	if tcp, ok := c.rwc.(closeWriter); ok {
		tcp.CloseWrite()
	}
	time.Sleep(rstAvoidanceDelay)
}
func putBufioReader(br *bufio.Reader) {
	br.Reset(nil)
	bufioReaderPool.Put(br)
}

func (c *conn) finalFlush() {
	if c.bufr != nil {
		// Steal the bufio.Reader (~4KB worth of memory) and its associated
		// reader for a future connection.
		putBufioReader(c.bufr)
		c.bufr = nil
	}

	if c.bufw != nil {
		c.bufw.Flush()
		// Steal the bufio.Writer (~4KB worth of memory) and its associated
		// writer for a future connection.
		putBufioWriter(c.bufw)
		c.bufw = nil
	}
}

//////////////////////////////
var (
	bufioReaderPool   sync.Pool
	bufioWriter2kPool sync.Pool
	bufioWriter4kPool sync.Pool
)

func newBufioReader(r io.Reader) *bufio.Reader {
	if v := bufioReaderPool.Get(); v != nil {
		br := v.(*bufio.Reader)
		br.Reset(r)
		return br
	}
	// Note: if this reader size is every changed, update
	// TestHandlerBodyClose's assumptions.
	return bufio.NewReader(r)
}

func newBufioWriterSize(w io.Writer, size int) *bufio.Writer {
	pool := bufioWriterPool(size)
	if pool != nil {
		if v := pool.Get(); v != nil {
			bw := v.(*bufio.Writer)
			bw.Reset(w)
			return bw
		}
	}
	return bufio.NewWriterSize(w, size)
}

func bufioWriterPool(size int) *sync.Pool {
	switch size {
	case 2 << 10:
		return &bufioWriter2kPool
	case 4 << 10:
		return &bufioWriter4kPool
	}
	return nil
}

func numLeadingCRorLF(v []byte) (n int) {
	for _, b := range v {
		if b == '\r' || b == '\n' {
			n++
			continue
		}
		break
	}
	return

}

func putBufioWriter(bw *bufio.Writer) {
	bw.Reset(nil)
	if pool := bufioWriterPool(bw.Available()); pool != nil {
		pool.Put(bw)
	}
}
