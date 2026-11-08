package pve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Front is the unistack-side machinery a PVE migration session drives.
//
// Everything project-specific (import windows, tokens, authorization,
// VM/volume lifecycle, placement, relaying to a compute node) lives
// behind this interface; pve itself only speaks the PVE wire protocol.
// The real implementation plugs into the project (todos/pve-import/05),
// StubFront keeps the package self-contained (and this repo's skeleton
// runnable) exactly like internal/libvirtin's StubFront.
//
// Session identity: every method receives the session id minted at
// mtunnel time; the Front keys its per-migration state by it.
type Front interface {
	// Claim is called right after the mtunnel POST: the source declared
	// which storages/bridges it will use (and the source VMID is known).
	// The Front reserves the target VM id, validates storages/bridges,
	// and creates the session. Returning an error fails the POST.
	Claim(ctx context.Context, p Principal, srcVMID int, storages, bridges []string) (sessionID string, err error)

	// Release tears the session down (quit, tunnel death). Idempotent.
	Release(ctx context.Context, sessionID string)

	// PrepareDisk answers {"cmd":"disk"}: allocate a receiving volume on
	// storage `storage` for one drive of the source VM. `slot` is the
	// drive slot (e.g. "scsi0"), drive the parsed source drive (its Raw
	// JSON carries cache/aio/iothread/… for the target volume config).
	// Returns the volid and the drivestr (e.g.
	// "scsi0:local-zfs:vm-201-disk-0") to report.
	//
	// The NBD export name must be ExportName(slot) — the Front exposes
	// exactly that export on the NBD server started by PrepareOnline
	// (vm.mirror_start / compute.NBDServerStart already do this).
	PrepareDisk(ctx context.Context, sessionID string, srcVMID int, slot, storage, format string, drive json.RawMessage) (volid, drivestr string, err error)

	// StageConfig answers {"cmd":"config"}: parse and store the PVE
	// .conf text (+ optional firewall config). Nothing is created yet.
	StageConfig(ctx context.Context, sessionID string, conf, firewall string) error

	// PrepareOnline answers {"cmd":"start"}: create the target VM
	// (stopped, incoming deferred), start the NBD server + per-drive
	// exports, and return the relay socket identifiers.
	//
	// UnixSockets must contain the RAM relay identifier
	// SocketPath(srcVMID, SocketSuffixMigrate) — the source asks a ticket
	// for exactly that path — plus any extra streams (spice, unused by
	// us). Drives maps source drive slot → NBDTarget{Drivestr (echo of
	// PrepareDisk), NBDURI: NBDURI(srcVMID, slot)}.
	PrepareOnline(ctx context.Context, sessionID string) (MigrateInfo, map[string]NBDTarget, error)

	// Resume answers {"cmd":"resume"}: the migration stream ended —
	// stop NBD serving and start the target (incoming) / finish
	// (outgoing). No-op on abort paths.
	Resume(ctx context.Context, sessionID string) error

	// NBDStop answers {"cmd":"nbdstop"}: stop serving NBD exports.
	NBDStop(ctx context.Context, sessionID string) error

	// FSTrim answers {"cmd":"fstrim"}: best-effort; report unsupported
	// with an error (the source logs a warning and proceeds).
	FSTrim(ctx context.Context, sessionID string) error

	// Stop answers {"cmd":"stop"} (failure teardown, api≥2): power the
	// target off / destroy it.
	Stop(ctx context.Context, sessionID string) error

	// Unlock answers {"cmd":"unlock"}: the source unlocks its VM and
	// asks us to release the target-side lock; we map it to releasing
	// the target reservation.
	Unlock(ctx context.Context, sessionID string) error

	// Relay answers a forwarded substream (control cmd "ticket" + new
	// WS connection with a minted ticket). The Front returns a raw
	// stream — e.g. a TCP connection to the compute node relay port —
	// which pve splices with the WebSocket until either side closes.
	//
	// path is the socket path from the ticket (always under
	// SocketPrefix); the Front maps it back to the target resource.
	Relay(ctx context.Context, sessionID, path string) (rc io.ReadCloser, wc io.WriteCloser, err error)

	// BeginImport answers {"cmd":"disk-import"} (cold path): create the
	// target volume named volname on storage and open a relay for the
	// import substream (socket = SocketPath(srcVMID, SocketSuffixStorage));
	// the payload arrives over Relay with the common 8-byte size header.
	// exportFormats is a comma-separated list of formats the source can
	// emit; we accept "raw" (the source converts qcow2/vmdk to raw), so
	// the Front must reject imports whose export_formats lack raw.
	// Returns the relay socket path and the accepted format ("raw").
	BeginImport(ctx context.Context, sessionID string, srcVMID int, req ImportRequest) (socket, format string, err error)

	// QueryImport answers {"cmd":"query-disk-import"}: ImportPending
	// until the stream is fully written and the volume finalized, then
	// ImportComplete with the target volid (ImportError + reason on
	// failure — the source shows the msg in its task log).
	QueryImport(ctx context.Context, sessionID string) (status, volid, msg string, err error)

	// --- read-only surface for the REST preflight (rest.go) ---

	// ReservedVMIDs lists target vmids currently held by import windows
	// of this principal (the source refuses an existing target vmid).
	ReservedVMIDs(ctx context.Context, p Principal) ([]int, error)

	// Storages lists import targets visible to the principal. Content
	// must include "images"; Type is a PVE storage type string
	// ("zfs"/"lvmthin"/"dir" …) shown in logs.
	Storages(ctx context.Context, p Principal) ([]StorageInfo, error)

	// CertificateFingerprint is the SHA-256 fingerprint of the TLS
	// certificate the ingress serves on 8006 ("AA:BB:…" uppercase,
	// `openssl x509 -fingerprint -sha256` form) — qm pins it via the
	// REST client and proxmox-websocket-tunnel compares it lowercased,
	// so exactly this string works for both.
	CertificateFingerprint(ctx context.Context) (string, error)

	// CustomCPUModel returns the CPU-options object of a custom model
	// the source VM uses (raw JSON as the PVE API returns it); ok=false
	// → 404, the source then refuses the migration.
	CustomCPUModel(ctx context.Context, model string) (raw json.RawMessage, ok bool, err error)
}

// StorageInfo is one entry of Front.Storages.
type StorageInfo struct {
	Storage string
	Type    string
	Content string // comma list, must contain "images"
	Shared  bool
	Total   int64
	Avail   int64
}

// StubFront is a no-op Front for tests and for wiring the package before
// the project integration (stage 05) exists. It records the last staged
// config and answers success to everything.
type StubFront struct {
	LastConf string
}

func (s *StubFront) Claim(context.Context, Principal, int, []string, []string) (string, error) {
	return NewSessionID()
}
func (s *StubFront) Release(context.Context, string) {}
func (s *StubFront) PrepareDisk(_ context.Context, _ string, srcVMID int, slot, storage, _ string, _ json.RawMessage) (string, string, error) {
	volid := fmt.Sprintf("%s:vm-%d/%s", storage, srcVMID, slot)
	return volid, slot + ":" + volid, nil
}
func (s *StubFront) StageConfig(_ context.Context, _ string, conf, _ string) error {
	s.LastConf = conf
	return nil
}
func (s *StubFront) PrepareOnline(_ context.Context, _ string) (MigrateInfo, map[string]NBDTarget, error) {
	return MigrateInfo{}, nil, errors.New("pve: StubFront does not support online migration")
}
func (s *StubFront) Resume(context.Context, string) error  { return nil }
func (s *StubFront) NBDStop(context.Context, string) error { return nil }
func (s *StubFront) FSTrim(context.Context, string) error {
	return errors.New("pve: fstrim not supported")
}
func (s *StubFront) Stop(context.Context, string) error   { return nil }
func (s *StubFront) Unlock(context.Context, string) error { return nil }
func (s *StubFront) Relay(context.Context, string, string) (io.ReadCloser, io.WriteCloser, error) {
	return nil, nil, errors.New("pve: StubFront does not relay")
}
func (s *StubFront) BeginImport(_ context.Context, _ string, _ int, req ImportRequest) (string, string, error) {
	return "", "", fmt.Errorf("pve: StubFront does not import %s", req.Volname)
}
func (s *StubFront) QueryImport(context.Context, string) (string, string, string, error) {
	return ImportPending, "", "", nil
}
func (s *StubFront) ReservedVMIDs(context.Context, Principal) ([]int, error) {
	return nil, nil
}
func (s *StubFront) Storages(context.Context, Principal) ([]StorageInfo, error) {
	return []StorageInfo{{Storage: "local", Type: "dir", Content: "images,rootdir", Total: 1 << 40, Avail: 1 << 40}}, nil
}
func (s *StubFront) CertificateFingerprint(context.Context) (string, error) {
	return "", nil
}
func (s *StubFront) CustomCPUModel(context.Context, string) (json.RawMessage, bool, error) {
	return nil, false, nil
}
