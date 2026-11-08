package pve

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// API token authentication.
//
// The source sends "Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<uuid>"
// (qemu-server prepends "PVEAPIToken=" when the operator pastes a bare
// tokenid=value). We map this onto the project import window (see
// todos/pve-import/01): the window holds sha256(value) and an optional
// source-IP allowlist. PVE users/realms/roles are not emulated: the token
// identifies exactly one project window.

// tokenRE matches "<user>@<realm>!<tokenid>" (PVE token id syntax).
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_.\-]+@[A-Za-z0-9.\-]+![A-Za-z0-9_\-\.]{1,32}$`)

// uuidRE matches the canonical UUID token value.
var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Principal is the authenticated scope of one ingress request.
type Principal struct {
	ProjectID string
	WindowID  string
	TokenID   string // "<user>@<realm>!<tokenid>", for audit
}

// TokenValidator validates an API token credential.
//
// Implementations must be uniform-deny: every failure (unknown token,
// closed window, expired, IP not allowed) returns some error and the
// caller replies with one indistinguishable 401 (NoCloud precedent,
// internal/vm/nocloud.go).
type TokenValidator interface {
	Validate(tokenID, value, sourceIP string) (Principal, error)
}

// ParseAuthorization extracts (tokenID, value) from an Authorization header
// value. Accepts the "PVEAPIToken=..." prefixed form and the bare
// "<tokenid>=<value>" form qemu-server sends for tokens without prefix.
func ParseAuthorization(header string) (tokenID, value string, err error) {
	h := strings.TrimSpace(header)
	if rest, ok := strings.CutPrefix(h, "PVEAPIToken="); ok {
		h = rest
	}
	id, val, ok := strings.Cut(h, "=")
	if !ok || id == "" || val == "" {
		return "", "", errors.New("pve: malformed api token")
	}
	if !tokenRE.MatchString(id) {
		return "", "", fmt.Errorf("pve: malformed token id %q", id)
	}
	if !uuidRE.MatchString(val) {
		return "", "", errors.New("pve: malformed token value")
	}
	return id, val, nil
}

// Tunnel tickets.
//
// Before opening any forwarded stream (RAM, NBD, cold-import) the source
// asks the control channel `{"cmd":"ticket","path":"/socket/<p>"}` and then
// opens a new WebSocket with ?ticket=…&socket=<p>. PVE signs these with the
// cluster RSA key over "user:/socket/<path>" with a −20..+40 s window
// (PVE::AccessControl verify_tunnel_ticket). We use a per-session HMAC key
// generated at mtunnel setup: the session dies with the migration, which is
// exactly the lifetime we want, and gives us revocation for free.
//
// Ticket wire format: "PVETUNNEL:<sid>:<unix-seconds-hex>:<hmac-hex>",
// where sid is the session id (opaque to the source — it only echoes the
// socket path back) and the HMAC covers sid|ts|user|path.

// TicketMinter mints and verifies path-bound tunnel tickets.
type TicketMinter struct {
	// Sessions resolves a session id minted by Mint to its HMAC secret.
	Sessions SessionKeyStore
	// Now is a clock hook; nil uses the wall clock.
	Now func() int64
}

// SessionKeyStore resolves session id → HMAC secret.
type SessionKeyStore interface {
	SessionSecret(sessionID string) ([]byte, bool)
}

func (m *TicketMinter) now() int64 {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now().Unix()
}

// NewSessionKey creates a fresh HMAC secret for a migration session.
func NewSessionKey() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("pve: gen session key: %w", err)
	}
	return b, nil
}

// NewSessionID creates an opaque session identifier.
func NewSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("pve: gen session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Mint creates a ticket for (user, path) bound to sessionID.
func (m *TicketMinter) Mint(sessionID, user, path string) (string, error) {
	secret, ok := m.Sessions.SessionSecret(sessionID)
	if !ok {
		return "", fmt.Errorf("pve: unknown session %q", sessionID)
	}
	ts := m.now()
	mac := ticketMAC(secret, sessionID, ts, user, path)
	return fmt.Sprintf("PVETUNNEL:%s:%016x:%s", sessionID, uint64(ts), hex.EncodeToString(mac)), nil
}

// Verify checks a ticket presented for (user, path). It enforces the
// PVE-equivalent age window [now+TicketMinAge, now+TicketMaxAge] and the
// path binding. The session id is not validated here (the caller looks it
// up to find the session); a forged sid fails the HMAC.
func (m *TicketMinter) Verify(ticket, user, path string) (sessionID string, err error) {
	parts := strings.Split(ticket, ":")
	if len(parts) != 4 || parts[0] != "PVETUNNEL" {
		return "", errors.New("pve: malformed tunnel ticket")
	}
	sid, tsHex, macHex := parts[1], parts[2], parts[3]
	u, err := strconv.ParseUint(tsHex, 16, 64)
	if err != nil {
		return "", errors.New("pve: malformed tunnel ticket ts")
	}
	ts := int64(u)
	age := m.now() - ts
	if age < TicketMinAge || age > TicketMaxAge {
		return "", fmt.Errorf("pve: tunnel ticket age %ds out of window", age)
	}
	want, ok := m.Sessions.SessionSecret(sid)
	if !ok {
		return "", errors.New("pve: tunnel ticket session not found")
	}
	wantMAC := ticketMAC(want, sid, ts, user, path)
	got, err := hex.DecodeString(macHex)
	if err != nil || subtle.ConstantTimeCompare(wantMAC, got) != 1 {
		return "", errors.New("pve: tunnel ticket verification failed")
	}
	return sid, nil
}

func ticketMAC(secret []byte, sessionID string, ts int64, user, path string) []byte {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "%s\n%d\n%s\n%s", sessionID, ts, user, path)
	return h.Sum(nil)
}
