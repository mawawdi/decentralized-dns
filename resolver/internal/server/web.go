package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/mawawdi/decentralized-dns/resolver/internal/query"
	bttorrent "github.com/mawawdi/decentralized-dns/resolver/internal/torrent"
)

// handleWeb is the decentralized-web gateway (HLD "Optional browser
// experience"). A standard browser visiting /web/<name> gets that domain's
// HTTP ResourceRef resolved, owner/SHA/ZK-verified and content-type-validated,
// then rendered inline — no browser extension or ddns:// protocol handler
// required, which is the honest, server-side form of the deferred nice-to-have.
//
// Unlike /resource (which returns a client-verifiable provenance envelope for
// CLIs), here the resolver acts as the trusted gateway and serves the bytes
// directly. The on-chain verification has already happened in
// fetchVerifiedResource, so what the browser renders is exactly what the owner
// signed and anchored.
func (s *Server) handleWeb(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	selector := r.URL.Query().Get("selector")
	selectorsToTry := []string{"service=HTTP", ""}
	if selector != "" {
		selectorsToTry = []string{selector}
	}

	ctx, cancel := context.WithTimeout(r.Context(), resourceFetchTimeout)
	defer cancel()

	var vr *verifiedResource
	var rerr *resourceError

	for _, sel := range selectorsToTry {
		pairs, err := query.ParsePairs(sel)
		if err != nil {
			continue
		}
		q, err := query.New(name, "ResourceRef", pairs)
		if err != nil {
			continue
		}
		vr, rerr = s.fetchVerifiedResource(ctx, q, s.resourcePeers(r))
		if rerr == nil {
			break
		}
		if rerr.code != "no_match" {
			break
		}
	}

	if rerr != nil {
		writeError(w, rerr.status, rerr.code, rerr.msg)
		return
	}

	h := w.Header()
	h.Set("Server", "Decentralized-DNS/2.0 (BitTorrent-P2P + Ethereum-Sepolia)")
	h.Set("Content-Type", vr.contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", webSandboxCSP)
	h.Set("Cache-Control", "no-cache, must-revalidate")

	var trackerParams string
	for _, tier := range bttorrent.PublicOpenTrackers {
		if len(tier) > 0 {
			trackerParams += "&tr=" + neturl.QueryEscape(tier[0])
		}
	}
	var peerParams string
	btPort := s.cfg.BTListenPort
	if btPort == 0 {
		btPort = 42069
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	if host != "" && host != "localhost" && host != "127.0.0.1" {
		peerParams += fmt.Sprintf("&x.pe=%s:%d", host, btPort)
	}
	if s.bt != nil {
		for _, addr := range s.bt.ListenAddrs() {
			if !strings.Contains(peerParams, addr) {
				peerParams += "&x.pe=" + addr
			}
		}
	}
	if !strings.Contains(peerParams, "127.0.0.1") {
		peerParams += fmt.Sprintf("&x.pe=127.0.0.1:%d", btPort)
	}
	magnetURI := fmt.Sprintf("magnet:?xt=urn:btih:%s&dn=%s.html%s%s", vr.infoHash, name, peerParams, trackerParams)

	// P2P BitTorrent & Blockchain Provenance Headers (inspectable via DevTools)
	h.Set("X-DDNS-Storage-Protocol", "BitTorrent (BEP-05 Mainline DHT / P2P Swarm)")
	h.Set("X-DDNS-InfoHash", vr.infoHash)
	h.Set("X-DDNS-Magnet", magnetURI)
	h.Set("X-DDNS-Owner", vr.owner)
	h.Set("X-DDNS-SHA256", vr.sha)
	h.Set("X-DDNS-Integrity-Status", "SHA-256 matched on-chain ResourceRef digest")
	h.Set("X-DDNS-Content-Validation", validationStatus(vr.validation.OK))

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(vr.body)
}
