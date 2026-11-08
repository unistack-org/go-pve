package pve

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Cold (offline) disk import wire format.
//
// On the <vmid>.storage substream the source runs its
// `pvesm export <volid> <format> -` and pipes the bytes to us; on the
// other end the destination's `pvesm import` writes them into the target
// volume. The stream is produced by PVE::Storage::run_common_header /
// read_common_header:
//
//	[8 bytes little-endian uint64 = uncompressed payload size][payload...]
//
// The payload format is what QemuMigrate negotiated via
// map_remote_import_format: tar (snapshots), vmdk (vmware), otherwise
// raw — qcow2/vmdk sources are converted to raw by the source with
// `qemu-img convert` before streaming, so what arrives is always raw
// bytes for our volumes.
//
// The length header lets the destination verify the transfer is complete
// ("written bytes == size") and preallocate/sparse-allocate. Real pvesm
// import writes with `dd conv=sparse`; we replicate that semantic: holes
// (all-zero blocks) are not written, so a thin volume stays thin.

// headerSize is the common header length in bytes.
const headerSize = 8

// maxImportSize caps an advertised payload (guards against a hostile
// header). 4 TiB per disk is far above anything MOEX-cloud will import.
const maxImportSize = 4 << 40

// ImportReader wraps a substream and exposes the framed payload.
type ImportReader struct {
	r    io.Reader
	size uint64
	read uint64
}

// NewImportReader reads and validates the common header.
func NewImportReader(r io.Reader) (*ImportReader, error) {
	hdr := make([]byte, headerSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("pve: read import header: %w", err)
	}
	size := binary.LittleEndian.Uint64(hdr)
	if size == 0 || size > maxImportSize {
		return nil, fmt.Errorf("pve: implausible import size %d", size)
	}
	return &ImportReader{r: r, size: size}, nil
}

// Size is the advertised uncompressed payload size.
func (ir *ImportReader) Size() uint64 { return ir.size }

// Read implements io.Reader over the payload only; it returns io.EOF
// exactly at the advertised size (a short stream → io.ErrUnexpectedEOF).
func (ir *ImportReader) Read(p []byte) (int, error) {
	if ir.read >= ir.size {
		return 0, io.EOF
	}
	if uint64(len(p)) > ir.size-ir.read {
		p = p[:ir.size-ir.read]
	}
	n, err := ir.r.Read(p)
	ir.read += uint64(n)
	if err == io.EOF && ir.read < ir.size {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

// Complete reports whether the full advertised payload was consumed.
func (ir *ImportReader) Complete() bool { return ir.read == ir.size }

// zeroBlock is the granularity at which we punch holes. 512 matches the
// logical block size of the qemu/KVM disks we import.
const zeroBlock = 512

// WriteSparse copies from ir into w, skipping all-zero 512-byte blocks.
// w must be a fresh sparse-capable file (O_CREATE|O_TRUNC on ext4/xfs, a
// new ZFS zvol, a new LVM thin volume, …) so the skipped offsets read back
// as zeros. Returns the number of payload bytes accounted (== Size()).
func WriteSparse(w io.Writer, ir *ImportReader) (int64, error) {
	buf := make([]byte, zeroBlock)
	var written int64
	for {
		n, err := io.ReadFull(ir, buf)
		if n > 0 {
			if !allZero(buf[:n]) {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return written, fmt.Errorf("pve: import write: %w", werr)
				}
			}
			written += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF && n == 0 {
			break
		}
		if err != nil {
			return written, err
		}
	}
	if !ir.Complete() {
		return written, io.ErrUnexpectedEOF
	}
	return written, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
