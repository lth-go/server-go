package serverGo

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// NewChunkedReader returns a new chunkedReader that translates the data read from r
// out of HTTP "chunked" format before returning it.
// The chunkedReader returns io.EOF when the final 0-length chunk is read.
//
// NewChunkedReader is not needed by normal applications. The http package
// automatically decodes chunking when reading response bodies.
func NewChunkedReader(r io.Reader) io.Reader {
	br := r.(*bufio.Reader)
	return &chunkedReader{r: br}
}

type chunkedReader struct {
	r   *bufio.Reader
	n   uint64 // unread bytes in chunk
	err error
	buf [2]byte
}

func (cr *chunkedReader) beginChunk() {
	// chunk-size CRLF
	var line []byte
	line, cr.err = readChunkLine(cr.r)
	if cr.err != nil {
		return
	}
	// 处理16进制数据
	cr.n, cr.err = parseHexUint(line)
	if cr.err != nil {
		return
	}
	if cr.n == 0 {
		cr.err = io.EOF
	}
}

func (cr *chunkedReader) chunkHeaderAvailable() bool {
	n := cr.r.Buffered()
	if n > 0 {
		peek, _ := cr.r.Peek(n)
		return bytes.IndexByte(peek, '\n') >= 0
	}
	return false
}

func (cr *chunkedReader) Read(b []uint8) (n int, err error) {
	for cr.err == nil {
		if cr.n == 0 {
			if n > 0 && !cr.chunkHeaderAvailable() {
				// We've read enough. Don't potentially block
				// reading a new chunk header.
				break
			}
			// 从远端读取数据
			cr.beginChunk()
			continue
		}
		if len(b) == 0 {
			break
		}
		rbuf := b
		if uint64(len(rbuf)) > cr.n {
			rbuf = rbuf[:cr.n]
		}
		var n0 int
		n0, cr.err = cr.r.Read(rbuf)
		n += n0
		b = b[n0:]
		cr.n -= uint64(n0)
		// If we're at the end of a chunk, read the next two
		// bytes to verify they are "\r\n".
		if cr.n == 0 && cr.err == nil {
			if _, cr.err = io.ReadFull(cr.r, cr.buf[:2]); cr.err == nil {
				if cr.buf[0] != '\r' || cr.buf[1] != '\n' {
					cr.err = errors.New("malformed chunked encoding")
				}
			}
		}
	}
	return n, cr.err
}

const maxLineLength = 4096 // assumed <= bufio.defaultBufSize
var ErrLineTooLong = errors.New("header line too long")

// Read a line of bytes (up to \n) from b.
// Give up if the line exceeds maxLineLength.
// The returned bytes are owned by the bufio.Reader
// so they are only valid until the next bufio read.
func readChunkLine(b *bufio.Reader) ([]byte, error) {
	p, err := b.ReadSlice('\n')
	if err != nil {
		// We always know when EOF is coming.
		// If the caller asked for a line, there should be a line.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		} else if err == bufio.ErrBufferFull {
			err = ErrLineTooLong
		}
		return nil, err
	}
	if len(p) >= maxLineLength {
		return nil, ErrLineTooLong
	}
	p = trimTrailingWhitespace(p)
	p, err = removeChunkExtension(p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func trimTrailingWhitespace(b []byte) []byte {
	for len(b) > 0 && isASCIISpace(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// removeChunkExtension removes any chunk-extension from p.
// For example,
//     "0" => "0"
//     "0;token" => "0"
//     "0;token=val" => "0"
//     `0;token="quoted string"` => "0"
func removeChunkExtension(p []byte) ([]byte, error) {
	semi := bytes.IndexByte(p, ';')
	if semi == -1 {
		return p, nil
	}
	// TODO: care about exact syntax of chunk extensions? We're
	// ignoring and stripping them anyway. For now just never
	// return an error.
	return p[:semi], nil
}

func parseHexUint(v []byte) (n uint64, err error) {
	for i, b := range v {
		switch {
		case '0' <= b && b <= '9':
			b = b - '0'
		case 'a' <= b && b <= 'f':
			b = b - 'a' + 10
		case 'A' <= b && b <= 'F':
			b = b - 'A' + 10
		default:
			return 0, errors.New("invalid byte in chunk length")
		}
		if i == 16 {
			return 0, errors.New("http chunk length too large")
		}
		n <<= 4
		n |= uint64(b)
	}
	return
}
