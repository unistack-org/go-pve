package pve

import (
	"encoding/json"
	"fmt"
)

// Every control-channel message is one JSON object per line
// (JSON-lines). The source (PVE::Tunnel::write_tunnel) writes
// "<json>\n" into its stdin pipe and reads one line back per command:
// strictly request→response, one request in flight, replies in order.
//
// Protocol v2 replies are {"success":true,...payload} /
// {"success":false,"msg":"reason\n"}; v1 replied the bare string "OK" and
// is not supported (we always answer api=2).

// Drive is the "drive" object the source sends in the `disk` command:
// the parsed drive config of the source VM with volid/format/file
// removed by the source (qemu-server sends "parsed drive information
// without volid and format"). We keep the original JSON for the Front
// (the full object is echoed back into the target's volume config via
// Front.PrepareDisk) and parse the fields we need ourselves.
type Drive struct {
	Raw json.RawMessage `json:"-"`

	Interface string  `json:"interface,omitempty"`
	Media     string  `json:"media,omitempty"` // "disk" | "cdrom"
	Protocol  string  `json:"protocol,omitempty"`
	Size      *uint64 `json:"size,omitempty"` // bytes
	// Everything else (cache, aio, iothread, serial, …) lives in Raw.
}

func (d *Drive) UnmarshalJSON(b []byte) error {
	type alias Drive
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*d = Drive(a)
	d.Raw = append(d.Raw[:0], b...)
	return nil
}

// Command is one control-channel request from the source, flattened.
//
// PVE validates every command with a schema (additionalProperties=0 for
// config/disk/start/ticket/quit/disk-import/bwlimit), so the source sends
// exactly these fields per command; commands without a schema entry
// (version, resume, stop, nbdstop, fstrim, unlock, query-disk-import)
// carry only "cmd".
type Command struct {
	Cmd string `json:"cmd"`

	// disk
	Format  string `json:"format,omitempty"`
	Storage string `json:"storage,omitempty"`
	Drive   *Drive `json:"drive,omitempty"`

	// config: full PVE .conf text of the VM (+ raw firewall config).
	Conf           string `json:"conf,omitempty"`
	FirewallConfig string `json:"firewall-config,omitempty"`

	// bwlimit (PVE::StorageTunnel::cmd_schema.bwlimit) — a query, not a
	// setting; the remote path in QemuMigrate never sends it.
	BWLimit BWLimitSpec `json:"bwlimit,omitempty"`

	// start
	StartParams json.RawMessage `json:"start_params,omitempty"`
	MigrateOpts json.RawMessage `json:"migrate_opts,omitempty"`

	// ticket
	Path string `json:"path,omitempty"`

	// quit: cleanup=1 → discard everything staged for this session.
	Cleanup *bool `json:"cleanup,omitempty"`

	// disk-import (PVE::StorageTunnel::cmd_schema['disk-import'])
	Volname           string `json:"volname,omitempty"`
	ExportFormats     string `json:"export_formats,omitempty"`
	Snapshot          string `json:"snapshot,omitempty"`
	MigrationSnapshot *bool  `json:"migration_snapshot,omitempty"`
	WithSnapshots     *bool  `json:"with_snapshots,omitempty"`
	AllowRename       *bool  `json:"allow_rename,omitempty"`
}

// BWLimitSpec is the bwlimit command payload.
type BWLimitSpec struct {
	Storages  []string `json:"storages,omitempty"`
	Limit     int      `json:"bwlimit,omitempty"`
	Operation string   `json:"operation,omitempty"`
}

// Reply is the base control-channel reply. Command handlers embed it and
// add their documented fields.
type Reply struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg,omitempty"`
}

// OK builds a success reply.
func OK() Reply { return Reply{Success: true} }

// Fail builds a failure reply. PVE puts a trailing newline in msg; the
// source shows it verbatim in the migration task log.
func Fail(format string, args ...interface{}) Reply {
	return Reply{Success: false, Msg: fmt.Sprintf(format, args...) + "\n"}
}

// versionReply answers CmdVersion.
type versionReply struct {
	Reply
	API int `json:"api"`
	Age int `json:"age"`
}

// diskReply answers CmdDisk: the allocated volume and how to reach it.
// Drivestr echoes the drive string the destination built (e.g.
// "scsi0:local-zfs:vm-201-disk-0"); the source keys its mirror job by it.
// Replicated=true tells the source the target reused a replicated volume
// (count must match the source's replicated disks) — we never replicate.
type diskReply struct {
	Reply
	Drivestr   string `json:"drivestr"`
	Volid      string `json:"volid"`
	Replicated *bool  `json:"replicated,omitempty"`
}

// MigrateInfo is the "migrate" object of startReply. The source asserts
// proto == "unix" (remote migration over non-UNIX sockets is refused by
// qemu-server) and forwards every socket in unix_sockets.
type MigrateInfo struct {
	Proto       string   `json:"proto"`
	Addr        string   `json:"addr,omitempty"`
	UnixSockets []string `json:"unix_sockets"`
}

// NBDTarget is one entry of the drives map in startReply. The source
// validates nbd_uri contains the REMOTE vmid and rewrites it to the local
// vmid before feeding drive-mirror, and records drivestr for logging and
// the nbdstop bookkeeping.
type NBDTarget struct {
	Drivestr string `json:"drivestr"`
	NBDURI   string `json:"nbd_uri"`
}

// startReply answers CmdStart.
type startReply struct {
	Reply
	Migrate   MigrateInfo          `json:"migrate"`
	Drives    map[string]NBDTarget `json:"drives,omitempty"`
	SpicePort *int                 `json:"spice_port,omitempty"`
}

// importReply answers CmdDiskImport: the socket the source must connect
// to for the raw disk stream, and the format chosen for the stream (we
// force "raw" — see import.go; the source converts qcow2/vmdk with
// qemu-img before streaming).
type importReply struct {
	Reply
	Socket string `json:"socket"`
	Format string `json:"format"`
}

// Import statuses of query-disk-import (client loops on "pending", stops
// on "complete" — new_volid — and "error").
const (
	ImportPending  = "pending"
	ImportComplete = "complete"
	ImportError    = "error"
)

// queryImportReply answers CmdQueryDiskImport.
type queryImportReply struct {
	Reply
	Status string `json:"status"`
	Volid  string `json:"volid,omitempty"`
}

// ticketReply answers CmdTicket for a forwarded stream.
type ticketReply struct {
	Reply
	Ticket string `json:"ticket"`
}

// ImportRequest is the disk-import payload handed to Front.BeginImport.
type ImportRequest struct {
	Volname           string
	Storage           string
	Format            string // preferred source format, e.g. "qcow2"
	ExportFormats     []string
	Snapshot          string
	MigrationSnapshot bool
	WithSnapshots     bool
	AllowRename       bool
}

// unmarshalCommand decodes a control-channel frame.
func unmarshalCommand(data []byte) (*Command, error) {
	c := &Command{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Envelope is the PVE REST reply wrapper: the payload always lives under
// "data" (PVE::APIClient::LWP unwraps it and dies on other shapes).
type Envelope struct {
	Data   interface{}     `json:"data"`
	Errors json.RawMessage `json:"errors,omitempty"`
}
