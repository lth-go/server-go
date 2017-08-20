package serverGo

import (
	"context"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
// TODO
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

type contextKey struct {
	name string
}

var (
	// ServerContextKey is a context key. It can be used in HTTP
	// handlers with context.WithValue to access the server that
	// started the handler. The associated value will be of
	// type *Server.
	ServerContextKey = &contextKey{"http-server"}

	// LocalAddrContextKey is a context key. It can be used in
	// HTTP handlers with context.WithValue to access the address
	// the local address the connection arrived on.
	// The associated value will be of type net.Addr.
	LocalAddrContextKey = &contextKey{"local-addr"}
)

// Server 服务器
type Server struct {
	Addr    string  // TCP address to listen on, ":http" if empty
	Handler Handler // handler to invoke, http.DefaultServeMux if nil

	// MaxHeaderBytes controls the maximum number of bytes the
	// server will read parsing the request header's keys and
	// values, including the request line. It does not limit the
	// size of the request body.
	// If zero, DefaultMaxHeaderBytes is used.
	MaxHeaderBytes int

	// ErrorLog specifies an optional logger for errors accepting
	// connections and unexpected behavior from handlers.
	// If nil, logging goes to os.Stderr via the log package's
	// standard logger.
	ErrorLog *log.Logger

	disableKeepAlives int32 // accessed atomically.
}

// Create new connection from rwc.
func (srv *Server) newConn(rwc net.Conn) *conn {
	return &conn{
		server: srv,
		rwc:    rwc,
	}

}

func (srv *Server) logf(format string, args ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// ListenAndServe 监听并运行服务
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}
	// 监听端口
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
}

// Serve 运行服务
func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()

	// TODO 上下文
	baseCtx := context.Background()
	ctx := context.WithValue(baseCtx, ServerContextKey, srv)
	ctx = context.WithValue(ctx, LocalAddrContextKey, l.Addr())
	for {
		rw, e := l.Accept()
		if e != nil {
			return e
		}
		c := srv.newConn(rw)
		// 连接
		go c.serve(ctx)
	}
}
func (srv *Server) doKeepAlives() bool {
	return atomic.LoadInt32(&srv.disableKeepAlives) == 0
}

// DefaultMaxHeaderBytes is the maximum permitted size of the headers
// in an HTTP request.
// This can be overridden by setting Server.MaxHeaderBytes.
const DefaultMaxHeaderBytes = 1 << 20 // 1 MB

func (srv *Server) maxHeaderBytes() int {
	if srv.MaxHeaderBytes > 0 {
		return srv.MaxHeaderBytes
	}
	return DefaultMaxHeaderBytes
}

func (srv *Server) initialReadLimitSize() int64 {
	return int64(srv.maxHeaderBytes()) + 4096 // bufio slop
}

// ListenAndServe 服务器入口函数
func ListenAndServe(addr string, handler Handler) error {
	server := &Server{Addr: addr, Handler: handler}
	return server.ListenAndServe()
}
