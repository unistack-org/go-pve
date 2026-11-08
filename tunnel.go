package pve

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/coder/websocket"
)

// The control channel is a byte stream of JSON lines bridged by the
// source's pveproxy ↔ WebSocket relay: pvewsproxy pumps raw stdin bytes
// into WS messages and raw WS message bytes into stdout, so messages are
// NOT guaranteed to align with lines (one message may carry several lines
// or half a line). We therefore treat every connection (control and
// forwarded) as an opaque byte stream and split JSON-lines ourselves.
//
// The control loop is strictly sequential (one request in flight, replies
// FIFO), which falls out naturally from single-goroutine read→handle→write.

// maxFrame guards against a hostile/buggy peer on the control channel.
const maxFrame = MaxControlFrame

// LineStream reads newline-delimited JSON objects from a WebSocket
// connection, buffering partial messages.
type LineStream struct {
	conn wsConn
	buf  []byte
}

// wsConn is the slice of *websocket.Conn the framing needs; tests inject
// a fake to simulate message/line boundaries.
type wsConn interface {
	Read(ctx context.Context) (websocket.MessageType, []byte, error)
	Write(ctx context.Context, t websocket.MessageType, data []byte) error
	Close(code websocket.StatusCode, reason string) error
}

// NewLineStream wraps conn. The peer must send text frames for the control
// channel (qemu-server does; pvewsproxy forwards raw bytes of whatever the
// client writes, typically text); we accept text and binary alike.
func NewLineStream(conn *websocket.Conn) *LineStream {
	return &LineStream{conn: conn}
}

// NewLineStreamFromConn wraps any wsConn (tests).
func NewLineStreamFromConn(c wsConn) *LineStream { return &LineStream{conn: c} }

// ReadLine returns the next complete JSON line (without the newline).
// It blocks across messages until a '\n' arrives. MaxControlFrame caps a
// single line.
func (s *LineStream) ReadLine(ctx context.Context) ([]byte, error) {
	for {
		if i := indexByte(s.buf, '\n'); i >= 0 {
			line := s.buf[:i]
			s.buf = s.buf[i+1:]
			if len(line) == 0 {
				continue // tolerate blank lines
			}
			out := make([]byte, len(line))
			copy(out, line)
			return out, nil
		}
		if len(s.buf) > maxFrame {
			return nil, fmt.Errorf("pve: control line exceeds %d bytes", maxFrame)
		}
		_, data, err := s.conn.Read(ctx)
		if err != nil {
			return nil, err
		}
		s.buf = append(s.buf, data...)
	}
}

// ReadCommand reads and decodes the next control command.
func (s *LineStream) ReadCommand(ctx context.Context) (*Command, error) {
	line, err := s.ReadLine(ctx)
	if err != nil {
		return nil, err
	}
	return unmarshalCommand(line)
}

// WriteReply encodes v as one JSON line. The trailing newline matters:
// the source splits replies on lines.
func (s *LineStream) WriteReply(ctx context.Context, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("pve: encode reply: %w", err)
	}
	data = append(data, '\n')
	return s.conn.Write(ctx, websocket.MessageText, data)
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// splice pumps bytes both ways between a WebSocket connection and a raw
// stream (the compute node's relay endpoint) until either side finishes.
// Used for every forwarded substream: RAM migrate, per-disk NBD,
// cold-import. Data flows as binary frames; we do not interpret it.
//
// The transfers are long-lived (a full-disk mirror can run for hours), so
// reads/writes are not bound by the request ctx; callers cancel by closing
// the connection (ws.Close / raw.Close unblocks the pump goroutines).
func splice(ws *websocket.Conn, raw net.Conn) error {
	errc := make(chan error, 2)
	go func() {
		// WS → raw
		for {
			_, data, err := ws.Read(context.Background())
			if err != nil {
				errc <- err
				return
			}
			if _, err := raw.Write(data); err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() {
		// raw → WS in chunks; we never interpret QEMU migration/NBD payloads.
		buf := make([]byte, 128*1024)
		for {
			n, err := raw.Read(buf)
			if n > 0 {
				if werr := ws.Write(context.Background(), websocket.MessageBinary, buf[:n]); werr != nil {
					errc <- werr
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				errc <- err
				return
			}
		}
	}()
	err := <-errc
	ws.Close(websocket.StatusNormalClosure, "")
	raw.Close()
	<-errc // reap the twin pump
	if errors.Is(err, io.EOF) || isNetClosed(err) {
		return nil
	}
	return err
}

func isNetClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// bufio convenience for import streams (import.go); declared here to keep
// the stream helpers together.
func newBufReader(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, 128*1024) }
