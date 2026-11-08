package pve

import (
	"strings"
	"testing"
	"time"
)

func TestParseAuthorization(t *testing.T) {
	const tok = "root@pam!migrationtoken"
	const val = "abcdef12-3456-7890-abcd-ef1234567890"
	ok := []string{
		"PVEAPIToken=" + tok + "=" + val,
		tok + "=" + val,
		"  PVEAPIToken=" + tok + "=" + val + "  ",
	}
	for _, h := range ok {
		id, v, err := ParseAuthorization(h)
		if err != nil || id != tok || v != val {
			t.Fatalf("reject/parse %q: id=%q v=%q err=%v", h, id, v, err)
		}
	}
	bad := []string{
		"",
		"PVEAPIToken=",
		tok,                      // no value
		tok + "=",                //
		"=" + val,                // no id
		"root@pam token=" + val,  // space in id
		"root@pam!tok en=" + val, // space in id
		"root@pam!tok=" + strings.ReplaceAll(val, "-", ""),
		"Bearer xyz",
		"root@pam!tok_en=ABC", // not a uuid
	}
	for _, h := range bad {
		if _, _, err := ParseAuthorization(h); err == nil {
			t.Fatalf("accepted %q", h)
		}
	}
}

type staticKeys struct{ m map[string][]byte }

func (s *staticKeys) SessionSecret(id string) ([]byte, bool) {
	k, ok := s.m[id]
	return k, ok
}

func TestTicketRoundTrip(t *testing.T) {
	key, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	now := int64(1_800_000_000)
	m := &TicketMinter{
		Sessions: &staticKeys{m: map[string][]byte{"sid1": key}},
		Now:      func() int64 { return now },
	}
	const user = "root@pam!t"
	const path = "/socket//run/qemu-server/101.mtunnel"

	tick, err := m.Mint("sid1", user, path)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := m.Verify(tick, user, path)
	if err != nil || sid != "sid1" {
		t.Fatalf("verify: sid=%q err=%v", sid, err)
	}

	// path binding
	if _, err := m.Verify(tick, user, "/socket/other"); err == nil {
		t.Fatal("ticket accepted for foreign path")
	}
	// user binding
	if _, err := m.Verify(tick, "other@pam!t", path); err == nil {
		t.Fatal("ticket accepted for foreign user")
	}
	// unknown session
	m2 := &TicketMinter{Sessions: &staticKeys{}, Now: m.Now}
	if _, err := m2.Verify(tick, user, path); err == nil {
		t.Fatal("ticket accepted for unknown session")
	}
	// age window
	late := &TicketMinter{Sessions: m.Sessions, Now: func() int64 { return now + TicketMinAge - 1 }}
	if _, err := late.Verify(tick, user, path); err == nil {
		t.Fatal("ticket accepted from the future beyond window")
	}
	old := &TicketMinter{Sessions: m.Sessions, Now: func() int64 { return now + TicketMaxAge + 1 }}
	if _, err := old.Verify(tick, user, path); err == nil {
		t.Fatal("expired ticket accepted")
	}
	// edges are inclusive
	edgeOld := &TicketMinter{Sessions: m.Sessions, Now: func() int64 { return now + TicketMaxAge }}
	if _, err := edgeOld.Verify(tick, user, path); err != nil {
		t.Fatalf("boundary age rejected: %v", err)
	}
	// clock skew inside window is fine (PVE tolerates -20s)
	skew := &TicketMinter{Sessions: m.Sessions, Now: func() int64 { return now - 19 }}
	if _, err := skew.Verify(tick, user, path); err != nil {
		t.Fatalf("in-window skew rejected: %v", err)
	}
	// tampered MAC
	parts := strings.Split(tick, ":")
	tampered := parts[0] + ":" + parts[1] + ":" + parts[2] + ":" + flipHex(parts[3])
	if _, err := m.Verify(tampered, user, path); err == nil {
		t.Fatal("tampered ticket accepted")
	}
}

func TestTicketTimeEncoding(t *testing.T) {
	// ts is the zero-padded uint64 hex of unix seconds; ':' never appears
	// inside a field, so Split(ticket, ":") == 4 parts for any clock.
	m := &TicketMinter{
		Sessions: &staticKeys{m: map[string][]byte{"s": make([]byte, 32)}},
		Now:      func() int64 { return time.Date(2286, 11, 3, 0, 0, 0, 0, time.UTC).Unix() },
	}
	tk, err := m.Mint("s", "u@pam!t", "/socket/x")
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(tk, ":")) != 4 {
		t.Fatalf("ticket not 4 colon-separated fields: %q", tk)
	}
	if _, err := m.Verify(tk, "u@pam!t", "/socket/x"); err != nil {
		t.Fatal(err)
	}
}

func flipHex(s string) string {
	b := []byte(s)
	if b[0] == 'a' {
		b[0] = 'b'
	} else {
		b[0] = 'a'
	}
	return string(b)
}
