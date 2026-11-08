package pve

import "fmt"

// WSTunnelVersion is PVE's WS_TUNNEL_VERSION (qemu-server PVE::QemuMigrate).
// We answer `version` with api=2, age=0. The source aborts when its own
// version is higher than ours, and when ours is more than `age` ahead;
// PVE 7.3 through 9.x all speak api 2, so one answer is compatible.
const WSTunnelVersion = 2

// Tunnel commands, from the mtunnel command loop in qemu-server's
// PVE::API2::Qemu. The command loop validates every payload with
// additionalProperties=0, so replies must carry exactly the documented
// fields — serialize with explicit structs, never map[string]any.
const (
	CmdVersion         = "version"
	CmdConfig          = "config"
	CmdBWLimit         = "bwlimit"
	CmdDisk            = "disk"
	CmdDiskImport      = "disk-import"
	CmdQueryDiskImport = "query-disk-import"
	CmdStart           = "start"
	CmdFSTrim          = "fstrim"
	CmdStop            = "stop"
	CmdNBDStop         = "nbdstop"
	CmdResume          = "resume"
	CmdUnlock          = "unlock"
	CmdTicket          = "ticket"
	CmdQuit            = "quit"
)

// REST paths of the PVE JSON API v2. This is the whole surface we implement.
const (
	PathClusterStatus    = "/api2/json/cluster/status"
	PathClusterResources = "/api2/json/cluster/resources"
	PathCustomCPUModels  = "/api2/json/cluster/qemu/custom-cpu-models"
	PathStorageList      = "/api2/json/nodes/localhost/storage"
	PathCertificatesInfo = "/api2/json/nodes/localhost/certificates/info"
)

// Socket path shape used by the tunnel protocol. The source validates these
// paths against ^/run/qemu-server/<vmid>\.migrate$ (and rewrites the remote
// vmid into the local vmid) — the check runs on the SOURCE machine, so the
// paths are identifiers that Front.Relay maps onto real backends. We return
// the source's vmid in the `start` reply so its validation passes.
const (
	SocketPrefix        = "/run/qemu-server/"
	SocketSuffixMigrate = ".migrate"
	SocketSuffixNBD     = "_nbd.migrate"
	SocketSuffixStorage = ".storage"
	SocketSuffixMTunnel = ".mtunnel"
)

// MaxControlFrame caps control-channel JSON lines. Proxmox's WS proxy caps
// frames at 128 KiB; the largest payload is `config`, which carries the
// whole .conf text.
const MaxControlFrame = 128 * 1024

// TunnelTicketLifetime is the accepted clock window of a tunnel ticket,
// mirroring PVE's verify_rsa_ticket(-20, 40) for PVETUNNEL tickets.
const (
	TicketMinAge = -20
	TicketMaxAge = 40
)

// SocketPath builds a tunnel socket identifier for the SOURCE's vmid.
// See the SocketPrefix docs: these are protocol identifiers, not our
// filesystem paths.
func SocketPath(srcVMID int, suffix string) string {
	return fmt.Sprintf("%s%d%s", SocketPrefix, srcVMID, suffix)
}

// NBDURI builds the drive-mirror URI the source dials into the NBD export
// we serve for one drive (export name = the drive id, e.g. "scsi0").
func NBDURI(srcVMID int, drive string) string {
	return fmt.Sprintf("nbd:unix:%s%d%s:exportname=%s",
		SocketPrefix, srcVMID, SocketSuffixNBD, drive)
}

// ExportName is the NBD export name for a drive.
func ExportName(drive string) string { return drive }
