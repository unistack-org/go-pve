# go-pve

Pure-Go **server** for *incoming* Proxmox migrations: the destination
endpoint that answers the stock Proxmox tool
[`qm remote-migrate`](https://pve.proxmox.com/pve-docs/qm.1.html), so a
customer's on-prem Proxmox node can push a VM (config, disks, RAM —
live or cold) into your platform **without any agent on the source**.

```
qm remote-migrate 101 201 \
  'host=cloud.example.com,apitoken=PVEAPIToken=root@pam!token=...,fingerprint=AA:BB:...' \
  --target-storage local-zfs=unistack-pool --target-bridge vmbr0=br-public --online
```

Unlike a libvirt `virsh migrate --listen` receiver, here **Proxmox dials
you**: the source opens HTTPS to your ingress (port 8006, your
certificate — its fingerprint is what the operator pastes) and
multiplexes control, disks and RAM over inbound WebSocket tunnels. The
source opens no inbound ports; you are in the data path.

## What is implemented

- **Preflight REST subset** (`/api2/json/...`, PVE `{"data":…}`
  envelope): `cluster/status`, `cluster/resources`,
  `nodes/<n>/storage`, `certificates/info`, `POST qemu/<vmid>/mtunnel`,
  `GET qemu/<vmid>/mtunnelwebsocket` — enough for `qm remote-migrate`
  preflight to pass.
- **Control channel**: strictly request→response JSON lines over WS text
  frames (`WS_TUNNEL_VERSION=2`): `version`, `disk`, `disk-import`,
  `query-disk-import`, `config`, `start`, `bwlimit`, `fstrim`, `stop`,
  `nbdstop`, `resume`, `unlock`, `ticket`, `quit`.
- **Bulk streams** as separate WS sessions after a `ticket` round trip:
  guest RAM (`<vmid>.migrate`), per-disk NBD (`<vmid>_nbd.migrate`),
  cold import (`<vmid>.storage`). Bytes are spliced verbatim to
  `Front.Relay` — the engine is byte-blind.
- **Auth**: API tokens in PVE shape (`PVEAPIToken=user@realm!id=uuid`)
  via `TokenValidator`, plus short-lived path-bound tunnel tickets.

## Embedding

The engine is a set of interfaces; the host application owns policy:

```go
srv := &pve.Server{
    Front:          myFront,          // storage/VM placement + relay
    TokenValidator: myValidator,      // API token → Principal
    TLSConfig:      tlsCfg,           // optional; TLS may also terminate at ingress
}
httpSrv := &http.Server{Addr: ":8006", Handler: srv.Handler()}
```

`Front` (see `front.go`) is where platform logic lives: map the PVE
`.conf` onto your VM/volume model, reserve VMIDs, accept disk streams
into your storage, and expose a relay endpoint (migration/NBD port) the
engine splices each bulk session to. `Front.Relay` returning
`io.ReadWriteCloser` is the only data-plane contract.

## Origin

Extracted from [unistack](https://github.com/unistack-org/unistack)
(`internal/pvein`), where it is the control-role ingress for the
project-level "import VM" feature (spec: incoming Proxmox migration,
ADR-034: disk/RAM data relayed to storage/compute roles). The unistack
import-window adapter (`internal/compute/import/pve`) implements
`Front`/`TokenValidator` over project import windows.

Design notes: see `doc.go`.

## Status / licensing

Apache-2.0. The package is a protocol engine, not a Proxmox clone: it
implements exactly the wire surface `qm remote-migrate` uses (plus the
`ovirt-img`-style tickets concept for tunnels), not the PVE REST API in
general. No affiliation with Proxmox.
