// Package pve implements the *incoming* Proxmox endpoint: the destination
// side of `qm remote-migrate`, so a customer's on-prem Proxmox node can push
// a VM (with its disks, live or cold) into unistack using the stock Proxmox
// tool:
//
//	qm remote-migrate 101 201 \
//	  'host=cloud.example.com,apitoken=PVEAPIToken=root@pam!token=...,fingerprint=AA:BB:...' \
//	  --target-storage local-zfs=unistack-pool --target-bridge vmbr0=br-public --online
//
// Design: docs/superpowers/specs/2026-11-07-incoming-proxmox-migration-design.md
//
//   - Unlike libvirtin, Proxmox dials US. The source opens HTTPS to our
//     ingress (port 8006, our certificate — its fingerprint is what the
//     operator pastes) and multiplexes control, disks and RAM over ONE
//     inbound WebSocket tunnel (WS_TUNNEL_VERSION=2). We are in the data
//     path; the source opens no inbound ports.
//
//   - The source first walks a preflight REST subset (cluster/status,
//     cluster/resources, nodes/localhost/storage, certificates/info,
//     POST qemu/<vmid>/mtunnel, GET .../mtunnelwebsocket) — rest.go.
//
//   - The control channel is strictly request→response, one request in
//     flight, JSON-lines over WS text frames. Commands: version, disk,
//     disk-import, query-disk-import, config, start, bwlimit, fstrim, stop,
//     nbdstop, resume, unlock, ticket, quit — server.go.
//
//   - Every bulk stream (guest RAM at <vmid>.migrate, per-disk NBD at
//     <vmid>_nbd.migrate, cold import at <vmid>.storage) is a NEW WS session
//     opened after a `ticket` round trip on the control channel. server.go
//     splices each session to a backend stream from Front.Relay (the
//     compute node's migration / NBD port). Bytes are blind: our TLS is
//     terminated at the ingress, inside the cell we use cell migration TLS.
//
//   - Auth: project import-window API token in PVE shape
//     (PVEAPIToken=user@realm!id=uuid) plus short-lived path-bound tunnel
//     tickets (auth.go). PVE's Sys.Incoming / VM.Allocate map onto "import
//     window open + quota + VMID allowed"; PVE roles are not emulated.
//
//   - The PVE .conf is parsed once into the unistack VM/volume/segment model
//     (front.go StageConfig) and never stored.
//
// This package is the protocol seam. It must not import internal/vm,
// internal/compute or any other domain. Front (front.go) is where the
// control plane wires the real receiving workflow (vm.prepare_incoming,
// vm.mirror_start, NBD — stage 08 of todos/vm-migration/).
package pve
