package pve

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// REST surface: the PVE JSON API v2 subset that `qm remote-migrate` walks
// before the tunnel opens. All replies use the PVE envelope {"data":…}
// (PVE::APIClient::LWP unwraps it; anything else is a hard error).
//
// Endpoints (paths are the public /api2/json/… forms; qm's client
// prefixes them itself):
//
//	GET  /api2/json/cluster/status
//	GET  /api2/json/cluster/resources?type=vm
//	GET  /api2/json/cluster/qemu/custom-cpu-models/<model>
//	GET  /api2/json/nodes/localhost/storage?enabled=1
//	GET  /api2/json/nodes/localhost/certificates/info
//	POST /api2/json/nodes/{node}/qemu/{vmid}/mtunnel?storages=&bridges=
//	GET  /api2/json/nodes/{node}/qemu/{vmid}/mtunnelwebsocket?ticket=&socket=
//
// Authentication is the project import-window API token presented in the
// PVE shape (PVEAPIToken=user@realm!id=uuid). Every failure answers one
// uniform 401 — like NoCloud token endpoints, we never leak which part of
// the credential was wrong.

// ServeHTTP routes the REST surface; it is the http.Handler to mount on
// the 8006 ingress listener.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	p := cleanPath(r.URL.Path)
	switch {
	case p == PathClusterStatus:
		s.writeData(w, r, s.clusterStatus(r))
	case p == PathClusterResources:
		s.writeData(w, r, s.clusterResources(r, principal))
	case p == PathStorageList:
		s.writeData(w, r, s.storageList(r, principal))
	case p == PathCertificatesInfo:
		s.writeData(w, r, s.certificatesInfo(r))
	case strings.HasPrefix(p, PathCustomCPUModels+"/"):
		s.customCPUModel(w, r, principal, strings.TrimPrefix(p, PathCustomCPUModels+"/"))
	case strings.HasSuffix(p, "/mtunnel") && r.Method == http.MethodPost:
		s.mtunnelPost(w, r, principal, p)
	case strings.HasSuffix(p, "/mtunnelwebsocket") && r.Method == http.MethodGet:
		s.ServeMTunnelWebSocket(w, r)
	default:
		logKV(r.Context(), "info", "unmatched REST path", "path", p, "method", r.Method)
		http.Error(w, `{"data":null,"errors":"unsupported endpoint"}`, http.StatusNotFound)
	}
}

func cleanPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimSuffix(p, "/")
}

// authenticate validates the API token and returns the principal.
// The tunnel websocket handler re-verifies via the ticket (pveproxy
// forwards the Authorization header on WS upgrades, so identity is
// consistent); the REST calls all require the token.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	id, value, err := ParseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		s.deny(w, r, "parse")
		return Principal{}, false
	}
	p, err := s.Validator.Validate(id, value, clientIP(r))
	if err != nil {
		s.deny(w, r, "validate")
		return Principal{}, false
	}
	return p, true
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request, stage string) {
	logKV(r.Context(), "info", "unauthorized", "path", r.URL.Path, "stage", stage, "ip", clientIP(r))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"data":null,"errors":{"auth":"authentication failure"}}`))
}

func clientIP(r *http.Request) string {
	host, _, ok := strings.Cut(r.RemoteAddr, ":")
	if !ok {
		return r.RemoteAddr
	}
	return host
}

// writeData answers with the PVE envelope.
func (s *Server) writeData(w http.ResponseWriter, r *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(Envelope{Data: data}); err != nil {
		logKV(r.Context(), "warn", "encode reply", "path", r.URL.Path, "err", err)
	}
}

// clusterStatus answers GET /api2/json/cluster/status.
//
// The source scans for the entry {type:"node", local:true} and adopts its
// name as the target node for every subsequent call (the mtunnel POST
// path embeds it, and its mtunnel handler rejects node != localhost and
// != this name). We present one fake node; its name must be stable.
func (s *Server) clusterStatus(r *http.Request) []map[string]interface{} {
	return []map[string]interface{}{
		{"type": "cluster", "name": NodeName, "quorum": true, "online": true},
		{"type": "node", "name": NodeName, "local": true, "online": 1,
			"maxcpu": 0, "maxmem": 0, "cpu": 0, "mem": 0, "maxdisk": 0, "disk": 0,
			"level": "", "status": "online", "ssl_version": "", "cluster_is_vm": false},
	}
}

// clusterResources answers GET /api2/json/cluster/resources?type=vm.
//
// The source refuses a target vmid that already exists remotely, so this
// must list the target vmids we currently hold (staged/running imports
// included).
func (s *Server) clusterResources(r *http.Request, p Principal) []map[string]interface{} {
	vmid, err := s.Front.ReservedVMIDs(r.Context(), p)
	if err != nil {
		logKV(r.Context(), "warn", "reserved vmids failed", "err", err)
		return []map[string]interface{}{}
	}
	out := make([]map[string]interface{}, 0, len(vmid))
	for _, v := range vmid {
		out = append(out, map[string]interface{}{
			"vmid": v, "name": fmt.Sprintf("pve-import-%d", v), "node": NodeName,
			"type": "qemu", "status": "importing",
		})
	}
	return out
}

// storageList answers GET /api2/json/nodes/localhost/storage?enabled=1.
//
// The source checks each --target-storage id appears and its content
// list contains "images".
func (s *Server) storageList(r *http.Request, p Principal) []map[string]interface{} {
	sts, err := s.Front.Storages(r.Context(), p)
	if err != nil {
		logKV(r.Context(), "warn", "storages failed", "err", err)
		return []map[string]interface{}{}
	}
	out := make([]map[string]interface{}, 0, len(sts))
	for _, st := range sts {
		out = append(out, map[string]interface{}{
			"storage": st.Storage, "type": st.Type, "content": st.Content,
			"active": 1, "enabled": 1, "digest": "pve",
			"total": st.Total, "avail": st.Avail, "used": 0,
			"shared": st.Shared, "node": NodeName,
		})
	}
	return out
}

// certificatesInfo answers GET /api2/json/nodes/localhost/certificates/info
// — consulted only when the operator gave no fingerprint: the source takes
// info[0].fingerprint and pins it. We report our ingress certificate.
func (s *Server) certificatesInfo(r *http.Request) []map[string]interface{} {
	fp, err := s.Front.CertificateFingerprint(r.Context())
	if err != nil || fp == "" {
		// An empty list makes the source die with a clear message
		// ("no certificate with fingerprint ...") — the operator must
		// pass fingerprint= explicitly.
		return []map[string]interface{}{}
	}
	// qm.pm only adopts entries whose filename is pveproxy-ssl.pem
	// (preferred) or pve-ssl.pem, and pins the value as a SHA-256
	// fingerprint (uppercase colon form, like
	// `openssl x509 -fingerprint -sha256`).
	return []map[string]interface{}{{
		"type": "fingerprint", "fingerprint": fp,
		"filename": "pveproxy-ssl.pem", "days_left": 3650, "status": "valid",
	}}
}

// customCPUModel answers GET /api2/json/cluster/qemu/custom-cpu-models/<model>
// — consulted only when the source VM uses a custom CPU model; the reply
// is the model's CPU-options object the source validates and compares for
// compatibility.
func (s *Server) customCPUModel(w http.ResponseWriter, r *http.Request, p Principal, model string) {
	raw, ok, err := s.Front.CustomCPUModel(r.Context(), model)
	if err != nil || !ok {
		http.Error(w, `{"data":null,"errors":{"model":"not found"}}`, http.StatusNotFound)
		return
	}
	s.writeData(w, r, raw)
}

// mtunnelPost answers POST /api2/json/nodes/{node}/qemu/{vmid}/mtunnel.
//
// node must be "localhost" or the node name from cluster/status (the
// source uses the latter); vmid is the TARGET vmid. Returns
// {upid,ticket,socket}: the socket path the control WS will bind to
// (path-bound ticket), an initial ticket for it, and an opaque upid
// (qm logs it verbatim; contents are not parsed).
func (s *Server) mtunnelPost(w http.ResponseWriter, r *http.Request, p Principal, path string) {
	node, vmid, ok := parseNodeVMID(path)
	if !ok || (node != "localhost" && node != NodeName) {
		http.Error(w, `{"data":null,"errors":{"node":"node needs to be 'localhost' or local hostname"}}`, http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	storages := splitList(q.Get("storages"))
	bridges := splitList(q.Get("bridges"))

	sessionID, socket, ticket, err := s.StartSession(r.Context(), p, vmid, storages, bridges)
	if err != nil {
		logKV(r.Context(), "warn", "mtunnel claim failed",
			"vmid", vmid, "token", p.TokenID, "err", err)
		// 500 with a PVE-shaped message; qm shows it to the operator.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"data":null,"errors":{"mtunnel":%s}}`, jsonMarshalString(err.Error()))
		return
	}
	logKV(r.Context(), "info", "mtunnel started",
		"session", sessionID, "vmid", vmid, "token", p.TokenID,
		"storages", strings.Join(storages, ","), "bridges", strings.Join(bridges, ","))
	s.writeData(w, r, map[string]interface{}{
		"upid":   fmt.Sprintf("UPID:%s:%08X:%08X:%08X:mtunnel:%d:%s", NodeName, sessionSeq(), sessionSeq(), sessionSeq(), vmid, p.TokenID),
		"ticket": ticket,
		"socket": socket,
	})
}

// parseNodeVMID extracts node+vmid from ".../nodes/<node>/qemu/<vmid>/mtunnel[websocket]".
func parseNodeVMID(path string) (node string, vmid int, ok bool) {
	parts := strings.Split(path, "/")
	for i := 0; i+3 < len(parts); i++ {
		if parts[i] == "nodes" && parts[i+2] == "qemu" {
			n := parts[i+1]
			var v int
			if _, err := fmt.Sscanf(parts[i+3], "%d", &v); err != nil || v <= 0 {
				return "", 0, false
			}
			return n, v, true
		}
	}
	return "", 0, false
}

func jsonMarshalString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `"error"`
	}
	return string(b)
}

// NodeName is the node identity we present to the source. The tunnel
// protocol uses it in every socket path context; it must be stable and a
// valid PVE node name.
const NodeName = "unistack"

// sessionSeq makes upid strings look real (qm only prints them).
func sessionSeq() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b[:])
}
