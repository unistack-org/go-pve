package pve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// --- test doubles -------------------------------------------------------

type testValidator struct {
	t         *testing.T
	token     string // "<user>@<realm>!<id>"
	value     string // uuid
	principal Principal
}

func (v *testValidator) Validate(tokenID, value, _ string) (Principal, error) {
	if tokenID == v.token && value == v.value {
		return v.principal, nil
	}
	return Principal{}, fmt.Errorf("bad token")
}

type memKeys struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (k *memKeys) Put(id string, key []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string][]byte{}
	}
	k.m[id] = key
}
func (k *memKeys) SessionSecret(id string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key, ok := k.m[id]
	return key, ok
}
func (k *memKeys) Delete(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, id)
}

// recordingFront logs the command sequence and streams a cold import.
type recordingFront struct {
	StubFront
	mu       sync.Mutex
	log      []string
	received io.Reader // bytes streamed by the source (cold import)
	mu2      sync.Mutex
}

func (f *recordingFront) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, name)
}

func (f *recordingFront) awaitReceived(t *testing.T) io.Reader {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		r := f.received
		f.mu.Unlock()
		if r != nil {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("relay stream never opened")
	return nil
}

func (f *recordingFront) claimed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *recordingFront) Claim(context.Context, Principal, int, []string, []string) (string, error) {
	f.record("claim")
	return "test-session", nil
}
func (f *recordingFront) Release(context.Context, string) { f.record("release") }
func (f *recordingFront) PrepareDisk(_ context.Context, _ string, src int, slot, storage, format string, _ json.RawMessage) (string, string, error) {
	f.record("disk:" + slot)
	return fmt.Sprintf("unistack-pool/vm-%d-disk-0", 201), fmt.Sprintf("unistack-pool:vm-%d-disk-0,file=/dev/zvol/unistack-pool/vm-%d-disk-0", 201, 201), nil
}
func (f *recordingFront) StageConfig(_ context.Context, _ string, conf, _ string) error {
	f.record("config")
	return nil
}
func (f *recordingFront) BeginImport(_ context.Context, _ string, _ int, req ImportRequest) (string, string, error) {
	f.record("disk-import:" + req.Storage)
	return SocketPath(201, SocketSuffixStorage), "raw", nil
}

// Relay returns the target-side ends of one forwarded stream: the server
// pumps bytes FROM the source into wc and TO the source from rc. Cold
// import is source→target only, so the recorded stream lands in
// received; the reverse direction just blocks until the pump closes it.
func (f *recordingFront) Relay(_ context.Context, _ string, socket string) (io.ReadCloser, io.WriteCloser, error) {
	f.record("relay:" + socket)
	// wc: bytes the server pumps FROM the source — surface them on
	// f.received. rc: bytes TO the source; cold import sends none, so a
	// pipe nobody writes to (the pump blocks until the stream closes).
	inR, inW := io.Pipe()
	blockR, _ := io.Pipe()
	f.mu.Lock()
	f.received = inR
	f.mu.Unlock()
	return io.NopCloser(blockR), writeCloser{inW}, nil
}

type writeCloser struct{ *io.PipeWriter }

func (w writeCloser) Close() error { return w.PipeWriter.Close() }

func newTestServer(t *testing.T) (*httptest.Server, *recordingFront, *testValidator) {
	t.Helper()
	front := &recordingFront{}
	val := &testValidator{
		t: t, token: "root@pam!migrationtoken",
		value:     "abcdef12-3456-7890-abcd-ef1234567890",
		principal: Principal{ProjectID: "p1", WindowID: "w1", TokenID: "root@pam!migrationtoken"},
	}
	srv := NewServer(front, val, &memKeys{})
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	return hs, front, val
}

func authHeader(v *testValidator) string {
	return "PVEAPIToken=" + v.token + "=" + v.value
}

// --- REST preflight ------------------------------------------------------

func TestRESTPreflight(t *testing.T) {
	hs, _, val := newTestServer(t)
	get := func(path string, wantStatus int) []byte {
		t.Helper()
		req, _ := http.NewRequest("GET", hs.URL+path, nil)
		req.Header.Set("Authorization", authHeader(val))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != wantStatus {
			t.Fatalf("%s: status %d body %s", path, resp.StatusCode, body)
		}
		return body
	}

	// unauthenticated → uniform 401
	resp, err := http.Get(hs.URL + PathClusterStatus)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", resp.StatusCode)
	}

	// cluster/status: exactly one local node entry
	var status struct {
		Data []struct {
			Type  string `json:"type"`
			Name  string `json:"name"`
			Local bool   `json:"local"`
		} `json:"data"`
	}
	json.Unmarshal(get(PathClusterStatus, 200), &status)
	node := ""
	for _, e := range status.Data {
		if e.Type == "node" && e.Local {
			node = e.Name
		}
	}
	if node == "" {
		t.Fatal("no local node entry in cluster/status")
	}

	// resources?type=vm: empty (fresh window, no held targets)
	var res struct {
		Data []map[string]interface{} `json:"data"`
	}
	json.Unmarshal(get(PathClusterResources+"?type=vm", 200), &res)
	if len(res.Data) != 0 {
		t.Fatalf("resources not empty: %v", res.Data)
	}

	// storage list: StubFront offers "local" with images content
	var sts struct {
		Data []struct {
			Storage string `json:"storage"`
			Content string `json:"content"`
			Enabled int    `json:"enabled"`
		} `json:"data"`
	}
	json.Unmarshal(get(PathStorageList+"?enabled=1", 200), &sts)
	found := false
	for _, s := range sts.Data {
		if s.Storage == "local" && strings.Contains(s.Content, "images") && s.Enabled == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("storage list lacks usable target: %+v", sts.Data)
	}

	// certificates: stub reports none → empty list (forces explicit fingerprint)
	var certs struct {
		Data []map[string]interface{} `json:"data"`
	}
	json.Unmarshal(get(PathCertificatesInfo, 200), &certs)
	if len(certs.Data) != 0 {
		t.Fatalf("unexpected certs: %v", certs.Data)
	}

	// mtunnel POST: returns {upid,ticket,socket}; socket is the source-vmid
	// mtunnel path; the ticket verifies against /socket/<socket>.
	body := &bytes.Buffer{}
	req, _ := http.NewRequest("POST",
		hs.URL+"/api2/json/nodes/"+node+"/qemu/201/mtunnel?storages=local&bridges=vmbr0", body)
	req.Header.Set("Authorization", authHeader(val))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("mtunnel POST status %d: %s", resp.StatusCode, b)
	}
	var mt struct {
		Data struct {
			UPID   string `json:"upid"`
			Ticket string `json:"ticket"`
			Socket string `json:"socket"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&mt); err != nil {
		t.Fatal(err)
	}
	if want := SocketPath(201, SocketSuffixMTunnel); mt.Data.Socket != want {
		t.Fatalf("socket = %q, want %q", mt.Data.Socket, want)
	}
	if mt.Data.UPID == "" || !strings.HasPrefix(mt.Data.UPID, "UPID:") {
		t.Fatalf("upid = %q", mt.Data.UPID)
	}
	sid, err := NewServer(nil, nil, &memKeys{}).Tickets.Verify(mt.Data.Ticket, val.token, "/socket/"+mt.Data.Socket)
	_ = sid
	if err == nil {
		t.Fatal("control ticket verified against a server that never minted it")
	}
}

// --- full control-loop scenario (cold import path) -----------------------

func dialWS(t *testing.T, hs *httptest.Server, query string, auth string) *websocket.Conn {
	t.Helper()
	u := "ws" + strings.TrimPrefix(hs.URL, "http") + "/api2/json/nodes/x/qemu/201/mtunnelwebsocket?" + query
	h := http.Header{}
	h.Set("Authorization", auth)
	conn, _, err := websocket.Dial(context.Background(), u, &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

type wsPeer struct {
	t    *testing.T
	conn *websocket.Conn
	buf  []byte
}

func (p *wsPeer) send(v interface{}) {
	p.t.Helper()
	data, _ := json.Marshal(v)
	data = append(data, '\n')
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.conn.Write(ctx, websocket.MessageText, data); err != nil {
		p.t.Fatal(err)
	}
}

func (p *wsPeer) recv(v interface{}) {
	p.t.Helper()
	for {
		if i := bytes.IndexByte(p.buf, '\n'); i >= 0 {
			line := p.buf[:i]
			p.buf = p.buf[i+1:]
			if len(line) == 0 {
				continue
			}
			if err := json.Unmarshal(line, v); err != nil {
				p.t.Fatalf("reply %q: %v", line, err)
			}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, data, err := p.conn.Read(ctx)
		cancel()
		if err != nil {
			p.t.Fatalf("read: %v", err)
		}
		p.buf = append(p.buf, data...)
	}
}

func mustOK(t *testing.T, r Reply, what string) {
	t.Helper()
	if !r.Success {
		t.Fatalf("%s failed: %s", what, r.Msg)
	}
}

func TestColdImportOverWebSocket(t *testing.T) {
	hs, front, val := newTestServer(t)

	// 1. mtunnel POST (as qm remote-migrate does)
	req, _ := http.NewRequest("POST",
		hs.URL+"/api2/json/nodes/localhost/qemu/201/mtunnel?storages=local", nil)
	req.Header.Set("Authorization", authHeader(val))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var mt struct {
		Data struct {
			Ticket string `json:"ticket"`
			Socket string `json:"socket"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&mt); err != nil {
		t.Fatal(err)
	}

	// 2. control channel
	ctrl := dialWS(t, hs,
		"ticket="+urlQueryEscape(mt.Data.Ticket)+"&socket="+urlQueryEscape(mt.Data.Socket),
		authHeader(val))
	peer := &wsPeer{t: t, conn: ctrl}

	// version handshake
	peer.send(map[string]string{"cmd": "version"})
	var vr struct {
		Reply
		API int `json:"api"`
		Age int `json:"age"`
	}
	peer.recv(&vr)
	mustOK(t, vr.Reply, "version")
	if vr.API != WSTunnelVersion {
		t.Fatalf("api = %d", vr.API)
	}

	// disk-import (cold path)
	peer.send(map[string]interface{}{
		"cmd": "disk-import", "volname": "import-101", "storage": "local",
		"format": "raw", "export_formats": "raw", "allow_rename": true,
	})
	var ir struct {
		Reply
		Socket string `json:"socket"`
		Format string `json:"format"`
	}
	peer.recv(&ir)
	mustOK(t, ir.Reply, "disk-import")
	if ir.Format != "raw" {
		t.Fatalf("format = %q", ir.Format)
	}

	// ticket for the import socket
	peer.send(map[string]interface{}{"cmd": "ticket", "path": "/socket/" + ir.Socket})
	var tr struct {
		Reply
		Ticket string `json:"ticket"`
	}
	peer.recv(&tr)
	mustOK(t, tr.Reply, "ticket")

	// ticket for a path this mtunnel never registered → success=false
	peer.send(map[string]interface{}{"cmd": "ticket", "path": "/socket//run/qemu-server/999.bogus"})
	var bad Reply
	peer.recv(&bad)
	if bad.Success {
		t.Fatal("ticket minted for unregistered socket")
	}

	// 3. stream a pvesm-export payload (8-byte LE size header + data)
	// over the import socket; the server must splice it into Front.
	payload := append(leHeader(4), 'u', 'n', 'i', 's')
	importWS := dialWS(t, hs,
		"ticket="+urlQueryEscape(tr.Ticket)+"&socket="+urlQueryEscape(ir.Socket),
		authHeader(val))
	wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := importWS.Write(wctx, websocket.MessageBinary, payload); err != nil {
		t.Fatal(err)
	}
	wcancel()
	got := make([]byte, len(payload))
	src := front.awaitReceived(t)
	if _, err := io.ReadFull(makeDeadlineReader(src), got); err != nil {
		t.Fatalf("relay received %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relay payload = %q, want %q", got, payload)
	}
	importWS.Close(websocket.StatusNormalClosure, "done")

	// 4. query-disk-import must be pending while the stream drains, and
	// StubFront answers pending → the source keeps polling. We stop the
	// control loop with quit.
	peer.send(map[string]interface{}{"cmd": "query-disk-import"})
	var qr struct {
		Reply
		Status string `json:"status"`
	}
	peer.recv(&qr)
	mustOK(t, qr.Reply, "query-disk-import")
	if qr.Status != ImportPending {
		t.Fatalf("status = %q", qr.Status)
	}

	// 5. quit with cleanup → Front.Stop + session release
	peer.send(map[string]interface{}{"cmd": "quit", "cleanup": true})
	var qr2 Reply
	peer.recv(&qr2)
	mustOK(t, qr2, "quit")

	// give the relay pump a moment to record, then check the log
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if contains(front.claimed(), "release") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	log := front.claimed()
	for _, want := range []string{"claim", "disk-import:local", "relay:" + SocketPath(201, SocketSuffixStorage), "release"} {
		if !contains(log, want) {
			t.Fatalf("front log %v missing %q", log, want)
		}
	}
}

func TestWebSocketRejectsBadTicket(t *testing.T) {
	hs, _, val := newTestServer(t)
	conn := dialWS(t, hs,
		"ticket="+urlQueryEscape("PVETUNNEL:ghost:0000000000000000:deadbeef")+
			"&socket="+urlQueryEscape(SocketPath(201, SocketSuffixMTunnel)),
		authHeader(val))
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := conn.Read(ctx)
	if err == nil {
		t.Fatal("server accepted a forged ticket")
	}
	// coder/websocket surfaces a peer close via CloseStatus, not errors.As.
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("err = %v (want policy violation close)", err)
	}
	if !strings.Contains(err.Error(), "ticket verification failed") {
		t.Fatalf("close reason missing: %v", err)
	}
}

func TestRESTAuthUniformDeny(t *testing.T) {
	hs, _, _ := newTestServer(t)
	bad := []string{"", "PVEAPIToken=nonsense", "PVEAPIToken=root@pam!x=not-a-uuid"}
	for _, h := range bad {
		req, _ := http.NewRequest("GET", hs.URL+PathClusterStatus, nil)
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("%q → %d", h, resp.StatusCode)
		}
		// identical body for every rejection (no oracle)
		if string(body) != `{"data":null,"errors":{"auth":"authentication failure"}}` {
			t.Fatalf("%q body = %s", h, body)
		}
	}
}

// makeDeadlineReader unblocks ReadFull with a deadline (io.Pipe has none).
type deadlineReader struct {
	r    io.Reader
	done chan struct{}
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := d.r.Read(p)
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(5 * time.Second):
		return 0, context.DeadlineExceeded
	}
}

func makeDeadlineReader(r io.Reader) io.Reader { return &deadlineReader{r: r} }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }
