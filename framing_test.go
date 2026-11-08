package pve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

func TestImportReaderHeaderAndBoundaries(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 100)
	stream := append(leHeader(uint64(len(payload))), payload...)

	ir, err := NewImportReader(bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if ir.Size() != 100 {
		t.Fatalf("size = %d, want 100", ir.Size())
	}
	got, err := io.ReadAll(ir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 100 || !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %d bytes", len(got))
	}
	if !ir.Complete() {
		t.Fatal("not complete")
	}
	// reading past the payload stays at EOF (trailing bytes invisible)
	if _, err := ir.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("want io.EOF, got %v", err)
	}
}

func TestImportReaderShortStream(t *testing.T) {
	stream := append(leHeader(50), make([]byte, 10)...)
	ir, err := NewImportReader(bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(ir)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want ErrUnexpectedEOF, got %v", err)
	}
}

func TestImportReaderImplausibleSize(t *testing.T) {
	for _, size := range []uint64{0, maxImportSize + 1} {
		stream := append(leHeader(size), 'x')
		if _, err := NewImportReader(bytes.NewReader(stream)); err == nil {
			t.Fatalf("size %d: want error", size)
		}
	}
}

func TestWriteSparsePunchesHoles(t *testing.T) {
	// 2 blocks of zeros, 1 block of data, trailing zeros (beyond header size)
	data := make([]byte, 3*zeroBlock)
	copy(data[2*zeroBlock:], []byte("hello"))
	stream := append(leHeader(uint64(len(data))), data...)

	ir, err := NewImportReader(bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	var w countingWriter
	n, err := WriteSparse(&w, ir)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(data)) {
		t.Fatalf("accounted %d, want %d", n, len(data))
	}
	// Only the non-zero 512-byte block (containing "hello") is written:
	// sparse semantics.
	if w.n != zeroBlock {
		t.Fatalf("wrote %d bytes, want %d (holes must be skipped)", w.n, zeroBlock)
	}
	if !strings.Contains(w.buf.String(), "hello") {
		t.Fatal("payload content lost")
	}
}

type countingWriter struct {
	buf bytes.Buffer
	n   int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += len(p)
	return c.buf.Write(p)
}

func leHeader(size uint64) []byte {
	h := make([]byte, 8)
	h[0] = byte(size)
	h[1] = byte(size >> 8)
	h[2] = byte(size >> 16)
	h[3] = byte(size >> 24)
	h[4] = byte(size >> 32)
	h[5] = byte(size >> 40)
	h[6] = byte(size >> 48)
	h[7] = byte(size >> 56)
	return h
}

func TestLineStreamSplitsAcrossMessages(t *testing.T) {
	ctx := context.Background()
	// Feed two commands where ONE message carries a full line + half of
	// the next, and the second message carries the rest — exactly what
	// pvewsproxy's byte-pump can deliver.
	a := `{"cmd":"version"}` + "\n" + `{"cmd":"disk","stor`
	b := `age":"local"}` + "\n"

	s := &LineStream{conn: &fakeWSConn{incoming: [][]byte{[]byte(a), []byte(b)}}}
	c1, err := s.ReadCommand(ctx)
	if err != nil || c1.Cmd != "version" {
		t.Fatalf("cmd1: %v %v", c1, err)
	}
	c2, err := s.ReadCommand(ctx)
	if err != nil || c2.Cmd != "disk" || c2.Storage != "local" {
		t.Fatalf("cmd2: %+v %v", c2, err)
	}
}

// fakeWSConn implements the read/write surface LineStream uses.
type fakeWSConn struct {
	incoming [][]byte
	written  [][]byte
	pos      int
}

func (f *fakeWSConn) Read(context.Context) (websocket.MessageType, []byte, error) {
	if f.pos >= len(f.incoming) {
		return websocket.MessageText, nil, io.EOF
	}
	d := f.incoming[f.pos]
	f.pos++
	return websocket.MessageText, d, nil
}

func (f *fakeWSConn) Write(_ context.Context, t websocket.MessageType, data []byte) error {
	if t != websocket.MessageText {
		return fmt.Errorf("control replies must be text frames, got %v", t)
	}
	f.written = append(f.written, data)
	return nil
}

func (f *fakeWSConn) Close(websocket.StatusCode, string) error { return nil }

func TestReplyHasTrailingNewline(t *testing.T) {
	f := &fakeWSConn{}
	s := NewLineStreamFromConn(f)
	if err := s.WriteReply(context.Background(), OK()); err != nil {
		t.Fatal(err)
	}
	if len(f.written) != 1 {
		t.Fatalf("written %d", len(f.written))
	}
	got := string(f.written[0])
	if got != "{\"success\":true}\n" {
		t.Fatalf("reply = %q", got)
	}
}
