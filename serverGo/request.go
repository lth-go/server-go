package serverGo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	defaultMaxMemory = 32 << 20 // 32 MB
)

// ErrMissingFile is returned by FormFile when the provided file field name
// is either not present in the request or not a file field.
var ErrMissingFile = errors.New("http: no such file")
var (
	ErrNotMultipart    = &ProtocolError{"request Content-Type isn't multipart/form-data"}
	ErrMissingBoundary = &ProtocolError{"no multipart boundary param in Content-Type"}
)

type badStringError struct {
	what string
	str  string
}

func (e *badStringError) Error() string { return fmt.Sprintf("%s %q", e.what, e.str) }

// A Request represents an HTTP request received by a server
// or to be sent by a client.
//
// The field semantics differ slightly between client and server
// usage. In addition to the notes on the fields below, see the
// documentation for Request.Write and RoundTripper.
type Request struct {
	// Method specifies the HTTP method (GET, POST, PUT, etc.).
	// For client requests an empty string means GET.
	Method string

	// URL specifies either the URI being requested (for server
	// requests) or the URL to access (for client requests).
	URL *url.URL

	// The protocol version for incoming server requests.
	Proto      string // "HTTP/1.0"
	ProtoMajor int    // 1
	ProtoMinor int    // 0

	// Header contains the request header fields either received
	// by the server or to be sent by the client.
	Header Header

	// Body is the request's body.
	Body io.ReadCloser

	// ContentLength records the length of the associated content.
	ContentLength int64

	// TransferEncoding lists the transfer encodings from outermost to
	// innermost. An empty list denotes the "identity" encoding.
	TransferEncoding []string

	// Close indicates whether to close the connection after
	// replying to this request (for servers) or after sending this
	// request and reading its response (for clients).
	Close bool

	// For server requests Host specifies the host on which the
	// URL is sought. Per RFC 2616, this is either the value of
	// the "Host" header or the host name given in the URL itself.
	Host string

	// Form contains the parsed form data, including both the URL
	// field's query parameters and the POST or PUT form data.
	// This field is only available after ParseForm is called.
	// The HTTP client ignores Form and uses Body instead.
	Form url.Values

	// PostForm contains the parsed form data from POST, PATCH,
	// or PUT body parameters.
	PostForm url.Values

	// MultipartForm is the parsed multipart form, including file uploads.
	// This field is only available after ParseMultipartForm is called.
	// The HTTP client ignores MultipartForm and uses Body instead.
	MultipartForm *multipart.Form

	// Trailer specifies additional headers that are sent after the request
	// body.
	Trailer Header

	// RemoteAddr allows HTTP servers and other software to record
	// the network address that sent the request, usually for
	// logging. This field is not filled in by ReadRequest and
	// has no defined format. The HTTP server in this package
	// sets RemoteAddr to an "IP:port" address before invoking a
	// handler.
	// This field is ignored by the HTTP client.
	RemoteAddr string

	// RequestURI is the unmodified Request-URI of the
	// Request-Line (RFC 2616, Section 5.1) as sent by the client
	// to a server. Usually the URL field should be used instead.
	// It is an error to set this field in an HTTP client request.
	RequestURI string

	// ctx is either the client or server context. It should only
	// be modified via copying the whole Request using WithContext.
	// It is unexported to prevent people from using Context wrong
	// and mutating the contexts held by callers of the same request.
	ctx context.Context
}

// ProtoAtLeast reports whether the HTTP protocol used
// in the request is at least major.minor.
func (r *Request) ProtoAtLeast(major, minor int) bool {
	return r.ProtoMajor > major ||
		r.ProtoMajor == major && r.ProtoMinor >= minor
}

// Cookies parses and returns the HTTP cookies sent with the request.
func (r *Request) Cookies() []*Cookie {
	return readCookies(r.Header, "")
}

// ErrNoCookie is returned by Request's Cookie method when a cookie is not found.
var ErrNoCookie = errors.New("http: named cookie not present")

// Cookie returns the named cookie provided in the request or
// ErrNoCookie if not found.
func (r *Request) Cookie(name string) (*Cookie, error) {
	for _, c := range readCookies(r.Header, name) {
		return c, nil
	}
	return nil, ErrNoCookie
}

// AddCookie adds a cookie to the request. Per RFC 6265 section 5.4,
// AddCookie does not attach more than one Cookie header field. That
// means all cookies, if any, are written into the same line,
// separated by semicolon.
func (r *Request) AddCookie(c *Cookie) {
	s := fmt.Sprintf("%s=%s", sanitizeCookieName(c.Name), sanitizeCookieValue(c.Value))
	if c := r.Header.Get("Cookie"); c != "" {
		r.Header.Set("Cookie", c+"; "+s)
	} else {
		r.Header.Set("Cookie", s)
	}
}

func (r *Request) wantsClose() bool {
	return hasToken(r.Header.get("Connection"), "close")
}

// FormFile returns the first file for the provided form key.
// FormFile calls ParseMultipartForm and ParseForm if necessary.
func (r *Request) FormFile(key string) (multipart.File, *multipart.FileHeader, error) {
	if r.MultipartForm == nil {
		err := r.ParseMultipartForm(defaultMaxMemory)
		if err != nil {
			return nil, nil, err
		}
	}
	if r.MultipartForm != nil && r.MultipartForm.File != nil {
		if fhs := r.MultipartForm.File[key]; len(fhs) > 0 {
			f, err := fhs[0].Open()
			return f, fhs[0], err
		}
	}
	return nil, nil, ErrMissingFile
}

// FormValue returns the first value for the named component of the query.
// POST and PUT body parameters take precedence over URL query string values.
// FormValue calls ParseMultipartForm and ParseForm if necessary and ignores
// any errors returned by these functions.
// If key is not present, FormValue returns the empty string.
// To access multiple values of the same key, call ParseForm and
// then inspect Request.Form directly.
func (r *Request) FormValue(key string) string {
	if r.Form == nil {
		r.ParseMultipartForm(defaultMaxMemory)
	}
	if vs := r.Form[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// PostFormValue returns the first value for the named component of the POST
// or PUT request body. URL query parameters are ignored.
// PostFormValue calls ParseMultipartForm and ParseForm if necessary and ignores
// any errors returned by these functions.
// If key is not present, PostFormValue returns the empty string.
func (r *Request) PostFormValue(key string) string {
	if r.PostForm == nil {
		r.ParseMultipartForm(defaultMaxMemory)
	}
	if vs := r.PostForm[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func copyValues(dst, src url.Values) {
	for k, vs := range src {
		for _, value := range vs {
			dst.Add(k, value)
		}
	}
}

func parsePostForm(r *Request) (vs url.Values, err error) {
	if r.Body == nil {
		err = errors.New("missing form body")
		return
	}
	ct := r.Header.Get("Content-Type")
	// RFC 2616, section 7.2.1 - empty type
	//   SHOULD be treated as application/octet-stream
	if ct == "" {
		ct = "application/octet-stream"
	}
	ct, _, err = mime.ParseMediaType(ct)
	switch {
	case ct == "application/x-www-form-urlencoded":
		var reader io.Reader = r.Body
		maxFormSize := int64(1<<63 - 1)
		if _, ok := r.Body.(*maxBytesReader); !ok {
			maxFormSize = int64(10 << 20) // 10 MB is a lot of text.
			reader = io.LimitReader(r.Body, maxFormSize+1)
		}
		b, e := ioutil.ReadAll(reader)
		if e != nil {
			if err == nil {
				err = e
			}
			break
		}
		if int64(len(b)) > maxFormSize {
			err = errors.New("http: POST too large")
			return
		}
		vs, e = url.ParseQuery(string(b))
		if err == nil {
			err = e
		}
	case ct == "multipart/form-data":
		// handled by ParseMultipartForm (which is calling us, or should be)
		// TODO(bradfitz): there are too many possible
		// orders to call too many functions here.
		// Clean this up and write more tests.
		// request_test.go contains the start of this,
		// in TestParseMultipartFormOrder and others.
	}
	return
}

// ParseForm parses the raw query from the URL and updates r.Form.
//
// For POST or PUT requests, it also parses the request body as a form and
// put the results into both r.PostForm and r.Form.
// POST and PUT body parameters take precedence over URL query string values
// in r.Form.
//
// If the request Body's size has not already been limited by MaxBytesReader,
// the size is capped at 10MB.
//
// ParseMultipartForm calls ParseForm automatically.
// It is idempotent.
func (r *Request) ParseForm() error {
	var err error
	if r.PostForm == nil {
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			r.PostForm, err = parsePostForm(r)
		}
		if r.PostForm == nil {
			r.PostForm = make(url.Values)
		}
	}
	if r.Form == nil {
		if len(r.PostForm) > 0 {
			r.Form = make(url.Values)
			copyValues(r.Form, r.PostForm)
		}
		var newValues url.Values
		if r.URL != nil {
			var e error
			newValues, e = url.ParseQuery(r.URL.RawQuery)
			if err == nil {
				err = e
			}
		}
		if newValues == nil {
			newValues = make(url.Values)
		}
		if r.Form == nil {
			r.Form = newValues
		} else {
			copyValues(r.Form, newValues)
		}
	}
	return err
}

// ParseMultipartForm parses a request body as multipart/form-data.
// The whole request body is parsed and up to a total of maxMemory bytes of
// its file parts are stored in memory, with the remainder stored on
// disk in temporary files.
// ParseMultipartForm calls ParseForm if necessary.
// After one call to ParseMultipartForm, subsequent calls have no effect.
func (r *Request) ParseMultipartForm(maxMemory int64) error {
	if r.Form == nil {
		err := r.ParseForm()
		if err != nil {
			return err
		}
	}
	if r.MultipartForm != nil {
		return nil
	}

	mr, err := r.multipartReader()
	if err != nil {
		return err
	}

	f, err := mr.ReadForm(maxMemory)
	if err != nil {
		return err
	}

	if r.PostForm == nil {
		r.PostForm = make(url.Values)
	}
	for k, v := range f.Value {
		r.Form[k] = append(r.Form[k], v...)
		// r.PostForm should also be populated. See Issue 9305.
		r.PostForm[k] = append(r.PostForm[k], v...)
	}

	r.MultipartForm = f

	return nil
}
func (r *Request) multipartReader() (*multipart.Reader, error) {
	v := r.Header.Get("Content-Type")
	if v == "" {
		return nil, ErrNotMultipart
	}
	d, params, err := mime.ParseMediaType(v)
	if err != nil || d != "multipart/form-data" {
		return nil, ErrNotMultipart
	}
	boundary, ok := params["boundary"]
	if !ok {
		return nil, ErrMissingBoundary
	}
	return multipart.NewReader(r.Body, boundary), nil
}

type maxBytesReader struct {
	w   ResponseWriter
	r   io.ReadCloser // underlying reader
	n   int64         // max bytes remaining
	err error         // sticky error
}

func (l *maxBytesReader) tooLarge() (n int, err error) {
	l.err = errors.New("http: request body too large")
	return 0, l.err
}

func (l *maxBytesReader) Read(p []byte) (n int, err error) {
	if l.err != nil {
		return 0, l.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	// If they asked for a 32KB byte read but only 5 bytes are
	// remaining, no need to read 32KB. 6 bytes will answer the
	// question of the whether we hit the limit or go past it.
	if int64(len(p)) > l.n+1 {
		p = p[:l.n+1]
	}
	n, err = l.r.Read(p)

	if int64(n) <= l.n {
		l.n -= int64(n)
		l.err = err
		return n, err
	}

	n = int(l.n)
	l.n = 0

	// The server code and client code both use
	// maxBytesReader. This "requestTooLarge" check is
	// only used by the server code. To prevent binaries
	// which only using the HTTP Client code (such as
	// cmd/go) from also linking in the HTTP server, don't
	// use a static type assertion to the server
	// "*response" type. Check this interface instead:
	type requestTooLarger interface {
		requestTooLarge()
	}
	if res, ok := l.w.(requestTooLarger); ok {
		res.requestTooLarge()
	}
	l.err = errors.New("http: request body too large")
	return n, l.err
}

func (l *maxBytesReader) Close() error {
	return l.r.Close()
}

// ParseHTTPVersion ...
func ParseHTTPVersion(vers string) (major, minor int, ok bool) {
	const Big = 1000000 // arbitrary upper bound
	switch vers {
	case "HTTP/1.1":
		return 1, 1, true
	case "HTTP/1.0":
		return 1, 0, true
	}
	if !strings.HasPrefix(vers, "HTTP/") {
		return 0, 0, false
	}
	dot := strings.Index(vers, ".")
	if dot < 0 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(vers[5:dot])
	if err != nil || major < 0 || major > Big {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(vers[dot+1:])
	if err != nil || minor < 0 || minor > Big {
		return 0, 0, false
	}
	return major, minor, true
}

// parseRequestLine parses "GET /foo HTTP/1.1" into its three parts.
func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}
func readRequest(b *bufio.Reader) (req *Request, err error) {
	tp := newTextprotoReader(b)

	req = new(Request)

	// First line: GET /index.html HTTP/1.0
	// 读取第一行内容
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return nil, err
	}
	// 缓存
	defer func() {
		putTextprotoReader(tp)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	// 解析请求
	var ok bool
	req.Method, req.RequestURI, req.Proto, ok = parseRequestLine(s)
	print(req.Method, req.RequestURI, req.Proto)
	if !ok {
		return nil, &badStringError{"malformed HTTP request", s}
	}
	rawurl := req.RequestURI
	if req.ProtoMajor, req.ProtoMinor, ok = ParseHTTPVersion(req.Proto); !ok {
		return nil, &badStringError{"malformed HTTP version", req.Proto}
	}

	// 解析地址
	if req.URL, err = url.ParseRequestURI(rawurl); err != nil {
		return nil, err
	}

	// Subsequent lines: Key: value.
	// 读取请求头
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	req.Header = Header(mimeHeader)

	// RFC 2616: Must treat
	//	GET /index.html HTTP/1.1
	//	Host: www.google.com
	// and
	//	GET http://www.google.com/index.html HTTP/1.1
	//	Host: doesntmatter
	// the same. In the second case, any Host line is ignored.
	req.Host = req.URL.Host
	if req.Host == "" {
		req.Host = req.Header.get("Host")
	}

	// 在transfer中用到
	req.Close = shouldClose(req.ProtoMajor, req.ProtoMinor, req.Header, false)

	// 解析body
	err = readTransfer(req, b)
	if err != nil {
		return nil, err
	}

	return req, nil
}

var textprotoReaderPool sync.Pool

func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	if v := textprotoReaderPool.Get(); v != nil {
		tr := v.(*textproto.Reader)
		tr.R = br
		return tr
	}
	return textproto.NewReader(br)
}
func putTextprotoReader(r *textproto.Reader) {
	r.R = nil
	textprotoReaderPool.Put(r)
}
