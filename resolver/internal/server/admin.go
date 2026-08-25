package server

import (
	"context"
	"html/template"
	"net/http"
	"time"

	"github.com/mawawdi/decentralized-dns/resolver/internal/cache"
	bttorrent "github.com/mawawdi/decentralized-dns/resolver/internal/torrent"
)

// adminStats is the operator console snapshot (HLD §4.3): resolver identity,
// chain head, cache counters, and BitTorrent swarm health.
type adminStats struct {
	Resolver  string          `json:"resolver"`
	UptimeSec int64           `json:"uptimeSeconds"`
	ChainHead uint64          `json:"chainHead"`
	ChainOK   bool            `json:"chainOk"`
	RESTPort  int             `json:"restPort"`
	UDPPort   int             `json:"udpPort"`
	Cache     cache.Stats     `json:"cache"`
	Swarm     bttorrent.Stats `json:"swarm"`
}

// gatherStats assembles a console snapshot, degrading gracefully if the chain
// RPC is briefly unreachable or the torrent engine is disabled.
func (s *Server) gatherStats(ctx context.Context) adminStats {
	st := adminStats{
		Resolver:  s.identity.PublicKeyHex(),
		UptimeSec: int64(time.Since(s.startTime).Seconds()),
		RESTPort:  s.cfg.RESTPort,
		UDPPort:   s.cfg.UDPPort,
		Cache:     s.cache.Stats(),
	}
	if head, err := s.chain.ChainHead(ctx); err == nil {
		st.ChainHead = head
		st.ChainOK = true
	}
	if s.bt != nil {
		st.Swarm = s.bt.Stats()
	}
	return st
}

// handleAdminStats serves the console snapshot as JSON for programmatic use.
func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.gatherStats(ctx))
}

// handleAdmin renders the minimal web dashboard described in the HLD: a
// self-contained, dependency-free page that auto-refreshes every few seconds.
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminTemplate.Execute(w, s.gatherStats(ctx)); err != nil {
		s.log.Warn("admin render failed", "err", err)
	}
}

var adminTemplate = template.Must(template.New("admin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ddns resolver · console</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
         background: #0b0f14; color: #d7e0ea; padding: 2rem; }
  h1 { font-size: 1.3rem; margin: 0 0 .25rem; }
  .sub { color: #6b7c90; margin: 0 0 1.5rem; }
  a { color: #5ec2ff; }
  .grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
  .card { background: #121823; border: 1px solid #1e2a38; border-radius: 10px; padding: 1rem 1.1rem; }
  .card h2 { font-size: .72rem; text-transform: uppercase; letter-spacing: .08em;
             color: #6b7c90; margin: 0 0 .5rem; }
  .big { font-size: 1.8rem; font-weight: 600; }
  .ok { color: #4ade80; } .bad { color: #f87171; }
  code { word-break: break-all; color: #9fd2ff; }
  .row { display: flex; justify-content: space-between; gap: 1rem; }
  .row + .row { margin-top: .3rem; }
  .k { color: #6b7c90; }
</style>
</head>
<body>
  <h1>Decentralized DNS — Resolver Console</h1>
  <p class="sub">auto-refreshing every 5s · <a href="/admin/stats">raw JSON</a></p>
  <div class="grid">
    <div class="card">
      <h2>Resolver identity (ed25519)</h2>
      <code>{{.Resolver}}</code>
    </div>
    <div class="card">
      <h2>Chain head</h2>
      {{if .ChainOK}}<span class="big ok">#{{.ChainHead}}</span>{{else}}<span class="big bad">unreachable</span>{{end}}
    </div>
    <div class="card">
      <h2>TTL cache</h2>
      <div class="row"><span class="k">entries</span><span>{{.Cache.Entries}} / {{.Cache.Capacity}}</span></div>
      <div class="row"><span class="k">hits</span><span>{{.Cache.Hits}}</span></div>
      <div class="row"><span class="k">misses</span><span>{{.Cache.Misses}}</span></div>
      <div class="row"><span class="k">evictions</span><span>{{.Cache.Evictions}}</span></div>
    </div>
    <div class="card">
      <h2>BitTorrent swarm</h2>
      <div class="row"><span class="k">torrents</span><span>{{.Swarm.Torrents}}</span></div>
      <div class="row"><span class="k">peers</span><span>{{.Swarm.TotalPeers}}</span></div>
      <div class="row"><span class="k">bytes shared</span><span>{{.Swarm.BytesShared}}</span></div>
    </div>
    <div class="card">
      <h2>Process</h2>
      <div class="row"><span class="k">uptime</span><span>{{.UptimeSec}}s</span></div>
      <div class="row"><span class="k">REST port</span><span>{{.RESTPort}}</span></div>
      <div class="row"><span class="k">UDP port</span><span>{{.UDPPort}}</span></div>
    </div>
  </div>
</body>
</html>
`))
