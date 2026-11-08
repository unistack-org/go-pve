package pve

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Server is the ingress WebSocket surface of one PVE import endpoint:
// the mtunnel POST (REST, rest.go) hands sessions to it, and it serves
// GET /api2/json/nodes/{node}/qemu/{vmid}/mtunnelwebsocket.
//
// One migration = one control WS (socket = the session's mtunnel socket
// path) + N forwarded WS connections (RAM, one per NBD disk, cold-import),
// each opened with a ticket minted on the control channel for its exact
// socket path. Forwarded connections are spliced verbatim to
// Front.Relay streams; the control connection runs the command loop.
type Server struct {
	Front     Front
	Validator TokenValidator
	// Tickets mints per-session tunnel tickets; Sessions backs it.
	Tickets  *TicketMinter
	Sessions SessionKeyStore

	mu       sync.Mutex
	sessions map[string]*session

	// keys is Sessions when it also supports Put/Delete (SessionMap
	// does); the server then owns session-key lifecycle.
	keys SessionKeyWriter
}

// SessionKeyWriter is implemented by SessionKeyStores that let the Server
// register and remove per-session HMAC secrets.
type SessionKeyWriter interface {
	SessionKeyStore
	Put(sessionID string, key []byte)
	Delete(sessionID string)
}

// session is the per-migration state shared by the control loop and the
// forwarded-stream endpoints.
type session struct {
	id        string
	key       []byte // HMAC secret for tickets
	principal Principal
	srcVMID   int
	// sockets the source may open (path → kind); seeded by the control
	// loop as the migration progresses.
	sockets map[string]string
	closed  bool
}

// NewServer wires the required collaborators and returns a ready Server.
func NewServer(f Front, v TokenValidator, sessions SessionKeyStore) *Server {
	sv := &Server{
		Front:     f,
		Validator: v,
		Sessions:  sessions,
		Tickets:   &TicketMinter{Sessions: sessions},
		sessions:  map[string]*session{},
	}
	if kw, ok := sessions.(SessionKeyWriter); ok {
		sv.keys = kw
	}
	return sv
}

// StartSession is called by the REST layer after mtunnel POST
// authentication. It creates the session (Front.Claim) and returns the
// session id; the source then connects the control WS presenting a ticket
// for the returned socket path.
func (s *Server) StartSession(ctx context.Context, p Principal, srcVMID int, storages, bridges []string) (sessionID, socket, ticket string, err error) {
	sessionID, err = s.Front.Claim(ctx, p, srcVMID, storages, bridges)
	if err != nil {
		return "", "", "", err
	}
	key, err := NewSessionKey()
	if err != nil {
		s.Front.Release(ctx, sessionID)
		return "", "", "", err
	}
	control := SocketPath(srcVMID, SocketSuffixMTunnel)
	sess := &session{
		id:        sessionID,
		key:       key,
		principal: p,
		srcVMID:   srcVMID,
		sockets:   map[string]string{control: "control"},
	}
	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.mu.Unlock()
	if s.keys != nil {
		s.keys.Put(sessionID, key)
	}

	// PVE binds tunnel tickets to "/socket/<path>" (verify_tunnel_ticket
	// is called with that spelling); mirror it so the same rule applies
	// to control and forwarded streams.
	ticket, err = s.Tickets.Mint(sessionID, p.TokenID, socketTicketPath(control))
	if err != nil {
		s.dropSession(ctx, sess, "mint control ticket")
		return "", "", "", err
	}
	return sessionID, control, ticket, nil
}

func (s *Server) getSession(id string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	return sess, ok && !sess.closed
}

// dropSession removes and releases a session; safe to call twice.
func (s *Server) dropSession(ctx context.Context, sess *session, reason string) {
	s.mu.Lock()
	if sess.closed {
		s.mu.Unlock()
		return
	}
	sess.closed = true
	delete(s.sessions, sess.id)
	s.mu.Unlock()
	if s.keys != nil {
		s.keys.Delete(sess.id)
	}
	logKV(ctx, "info", "session released",
		"session", sess.id, "src_vmid", sess.srcVMID,
		"reason", reason)
	s.Front.Release(ctx, sess.id)
}

// registerSocket records a path the source may open a stream for.
func (s *Server) registerSocket(sess *session, path, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.sockets[path] = kind
}

// ServeMTunnelWebSocket is the http.Handler for
// GET /api2/json/nodes/{node}/qemu/{vmid}/mtunnelwebsocket?ticket=&socket=.
// It mirrors what pveproxy does on a real PVE node: verify the tunnel
// ticket bound to "/socket/"+socket, then bridge the WebSocket — control
// loop for the mtunnel socket, raw splice for forwarded streams.
func (s *Server) ServeMTunnelWebSocket(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ticket, socket := q.Get("ticket"), q.Get("socket")
	user := PrincipalFromAuthorization(r.Header.Get("Authorization"))

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The client is proxmox-websocket-tunnel (Rust), not a browser.
		InsecureSkipVerify: true,
	})
	if err != nil {
		logKV(r.Context(), "warn", "ws accept failed", "err", err)
		return
	}

	sid, err := s.Tickets.Verify(ticket, user, socketTicketPath(socket))
	if err != nil {
		logKV(r.Context(), "warn", "ticket verify failed",
			"socket", socket, "err", err)
		conn.Close(websocket.StatusPolicyViolation, "ticket verification failed")
		return
	}
	sess, ok := s.getSession(sid)
	if !ok {
		conn.Close(websocket.StatusPolicyViolation, "unknown session")
		return
	}

	s.mu.Lock()
	kind, known := sess.sockets[socket]
	s.mu.Unlock()
	if !known {
		logKV(r.Context(), "warn", "stream for unregistered socket",
			"session", sid, "socket", socket)
		conn.Close(websocket.StatusPolicyViolation, "socket not registered")
		return
	}

	if kind == "control" {
		s.runControlLoop(r.Context(), conn, sess)
		return
	}
	s.runStream(r.Context(), conn, sess, socket)
}

// runStream splices one forwarded substream to its Front stream.
func (s *Server) runStream(ctx context.Context, conn *websocket.Conn, sess *session, socket string) {
	rc, wc, err := s.Front.Relay(ctx, sess.id, socket)
	if err != nil {
		logKV(ctx, "warn", "relay open failed",
			"session", sess.id, "socket", socket, "err", err)
		conn.Close(websocket.StatusInternalError, "relay unavailable")
		return
	}
	defer rc.Close()
	defer wc.Close()
	logKV(ctx, "info", "stream spliced",
		"session", sess.id, "socket", socket)
	splice(conn, duplex{Reader: rc, Writer: wc, Closer: multiCloser{rc, wc}})
	logKV(ctx, "info", "stream closed",
		"session", sess.id, "socket", socket)
}

// duplex adapts the split reader/writer of Front.Relay to net.Conn. The
// Addr/Deadline methods are unused by splice (which relies on Close to
// unblock pumps), so they report "not supported" like net.Pipe's pipe-addr.
type duplex struct {
	io.Reader
	io.Writer
	io.Closer // closer over both halves
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pve/pipe" }

var errNoDeadlines = errors.New("pve: deadlines not supported on relay pipe")

func (d duplex) LocalAddr() net.Addr              { return pipeAddr{} }
func (d duplex) RemoteAddr() net.Addr             { return pipeAddr{} }
func (d duplex) SetDeadline(time.Time) error      { return errNoDeadlines }
func (d duplex) SetReadDeadline(time.Time) error  { return errNoDeadlines }
func (d duplex) SetWriteDeadline(time.Time) error { return errNoDeadlines }
func (d duplex) Close() error                     { return d.Closer.Close() }

type multiCloser []io.Closer

func (mc multiCloser) Close() error {
	var first error
	for _, c := range mc {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// runControlLoop is the mtunnel command loop: one command in flight,
// replies in order (sequential read→handle→write satisfies the source's
// FIFO responder queue).
func (s *Server) runControlLoop(ctx context.Context, conn *websocket.Conn, sess *session) {
	defer func() { s.dropSession(ctx, sess, "control loop exit") }()
	in := NewLineStream(conn)
	for {
		cmd, err := in.ReadCommand(ctx)
		if err != nil {
			// EOF/close: the source's tunnel child died with the task.
			return
		}
		reply := s.handleCommand(ctx, conn, in, sess, cmd)
		if werr := in.WriteReply(ctx, reply); werr != nil {
			logKV(ctx, "warn", "reply write failed",
				"session", sess.id, "cmd", cmd.Cmd, "err", werr)
			return
		}
		if cmd.Cmd == CmdQuit {
			return
		}
	}
}

// handleCommand dispatches one control command to the Front.
//
// Every branch answers with exactly the fields qemu-server's command
// handling expects (its JSON schema is additionalProperties=0) — see the
// per-command comments.
func (s *Server) handleCommand(ctx context.Context, conn *websocket.Conn, in *LineStream, sess *session, cmd *Command) interface{} {
	switch cmd.Cmd {
	case CmdVersion:
		// The source: dies if remote api < its version, dies if remote
		// api > its version + age. PVE 7.3..9.x all speak api 2.
		return versionReply{Reply: OK(), API: WSTunnelVersion, Age: 0}

	case CmdDisk:
		if cmd.Drive == nil || cmd.Storage == "" {
			return Fail("disk command incomplete")
		}
		slot := driveSlot(cmd)
		volid, drivestr, err := s.Front.PrepareDisk(ctx, sess.id, sess.srcVMID, slot, cmd.Storage, cmd.Format, cmd.Drive.Raw)
		if err != nil {
			return Fail("unable to allocate volume for drive '%s' on storage '%s': %v", slot, cmd.Storage, err)
		}
		return diskReply{Reply: OK(), Drivestr: drivestr, Volid: volid}

	case CmdConfig:
		if cmd.Conf == "" {
			return Fail("no config received")
		}
		if err := s.Front.StageConfig(ctx, sess.id, cmd.Conf, cmd.FirewallConfig); err != nil {
			return Fail("unable to import VM config: %v", err)
		}
		return OK()

	case CmdStart:
		// The source passes start_params/migrate_opts (statefile "unix",
		// spice ticket, nets-host-mtu …). We create our own target VM
		// from the staged config; the payloads are logged for diagnosis
		// only.
		logKV(ctx, "info", "start",
			"session", sess.id,
			"start_params", string(cmd.StartParams),
			"migrate_opts", string(cmd.MigrateOpts))
		info, drives, err := s.Front.PrepareOnline(ctx, sess.id)
		if err != nil {
			return Fail("unable to start incoming migration: %v", err)
		}
		info.Proto = "unix" // the source asserts this
		s.registerSocket(sess, SocketPath(sess.srcVMID, SocketSuffixMigrate), "ram")
		s.registerSocket(sess, SocketPath(sess.srcVMID, SocketSuffixNBD), "nbd")
		return startReply{Reply: OK(), Migrate: info, Drives: drives}

	case CmdBWLimit:
		// A query, not a setting (PVE::StorageTunnel::handle_bwlimit);
		// the remote path never sends it. Answer unlimited.
		return OK()

	case CmdDiskImport:
		socket, format, err := s.Front.BeginImport(ctx, sess.id, sess.srcVMID, ImportRequest{
			Volname:           cmd.Volname,
			Storage:           cmd.Storage,
			Format:            cmd.Format,
			ExportFormats:     splitList(cmd.ExportFormats),
			Snapshot:          cmd.Snapshot,
			MigrationSnapshot: deref(cmd.MigrationSnapshot),
			WithSnapshots:     deref(cmd.WithSnapshots),
			AllowRename:       deref(cmd.AllowRename),
		})
		if err != nil {
			return Fail("disk-import failed: %v", err)
		}
		s.registerSocket(sess, socket, "import")
		return importReply{Reply: OK(), Socket: socket, Format: format}

	case CmdQueryDiskImport:
		status, volid, msg, err := s.Front.QueryImport(ctx, sess.id)
		if err != nil {
			return Fail("query-disk-import: %v", err)
		}
		r := queryImportReply{Reply: OK(), Status: status, Volid: volid}
		if msg != "" {
			r.Msg = msg + "\n"
		}
		return r

	case CmdTicket:
		// The source asks for a ticket with path == "/socket/<raw path>";
		// PVE requires the path to be one of the sockets this mtunnel
		// instance listens on (Qemu.pm matches m|^/socket/(.*)$| and
		// checks -msocketip/-socket registry). We key the session's
		// socket map by the raw path.
		p, ok := strings.CutPrefix(cmd.Path, "/socket/")
		if !ok || p == "" {
			return Fail("no path given")
		}
		s.mu.Lock()
		_, known := sess.sockets[p]
		s.mu.Unlock()
		if !known {
			return Fail("socket path for which the ticket should be valid must be known to current mtunnel instance")
		}
		t, err := s.Tickets.Mint(sess.id, sess.principal.TokenID, cmd.Path)
		if err != nil {
			return Fail("unable to mint ticket: %v", err)
		}
		return ticketReply{Reply: OK(), Ticket: t}

	case CmdNBDStop:
		return s.simple(ctx, sess, "nbdstop", s.Front.NBDStop)
	case CmdResume:
		return s.simple(ctx, sess, "resume", s.Front.Resume)
	case CmdFSTrim:
		// The source wraps fstrim in eval and only warns on error, so a
		// clean refusal is safe for guest agents we don't control.
		return s.simple(ctx, sess, "fstrim", s.Front.FSTrim)
	case CmdStop:
		return s.simple(ctx, sess, "stop", s.Front.Stop)
	case CmdUnlock:
		return s.simple(ctx, sess, "unlock", s.Front.Unlock)

	case CmdQuit:
		cleanup := deref(cmd.Cleanup)
		logKV(ctx, "info", "quit", "session", sess.id,
			"cleanup", cleanup)
		if cleanup {
			return s.simple(ctx, sess, "quit-cleanup", s.Front.Stop)
		}
		return OK()

	default:
		return Fail("unknown command '%s'", cmd.Cmd)
	}
}

func (s *Server) simple(ctx context.Context, sess *session, name string, fn func(context.Context, string) error) interface{} {
	if err := fn(ctx, sess.id); err != nil {
		logKV(ctx, "warn", ""+name+" failed",
			"session", sess.id, "err", err)
		return Fail("%s: %v", name, err)
	}
	return OK()
}

// helpers

func driveSlot(cmd *Command) string {
	if cmd.Drive != nil && cmd.Drive.Interface != "" {
		return cmd.Drive.Interface
	}
	return "unknown"
}

// socketTicketPath is the identity a tunnel ticket is bound to, matching
// PVE::AccessControl verify_tunnel_ticket("$user:/socket/$path").
func socketTicketPath(rawSocket string) string {
	return "/socket/" + rawSocket
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func deref(b *bool) bool { return b != nil && *b }

// PrincipalFromAuthorization extracts the audit string of the api token
// from a request (the full validation ran at the REST layer; the WS
// upgrade for forwarded streams re-sends the same header — pveproxy
// forwards it — and we only need identity for logging/ticket binding).
func PrincipalFromAuthorization(header string) string {
	id, _, err := ParseAuthorization(header)
	if err != nil {
		return ""
	}
	return id
}

// SessionMap is a ready SessionKeyStore for single-process deployments;
// multi-replica ingress needs shared state (spec §Q6).
type SessionMap struct {
	mu sync.Mutex
	m  map[string][]byte
}

func NewSessionMap() *SessionMap { return &SessionMap{m: map[string][]byte{}} }

func (sm *SessionMap) Put(id string, key []byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.m[id] = key
}

func (sm *SessionMap) SessionSecret(id string) ([]byte, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	k, ok := sm.m[id]
	return k, ok
}

func (sm *SessionMap) Delete(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.m, id)
}
