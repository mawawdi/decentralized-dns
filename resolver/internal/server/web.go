package server

import (
	"context"
	"net/http"

	"github.com/devCana/decentralized-dns/resolver/internal/query"
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
	h.Set("Content-Type", vr.contentType)
	// Honour the on-chain declared type exactly; never let the browser re-sniff
	// it into something the owner did not anchor.
	h.Set("X-Content-Type-Options", "nosniff")
	// Sandbox every served site into its own opaque origin (see webSandboxCSP):
	// otherwise all decentralized names would share one real origin (this
	// resolver's), breaking the cross-site isolation real DNS gives each domain.
	h.Set("Content-Security-Policy", webSandboxCSP)
	h.Set("X-DDNS-Owner", vr.owner)
	h.Set("X-DDNS-SHA256", vr.sha)
	h.Set("X-DDNS-Content-Validation", validationStatus(vr.validation.OK))
	h.Set("Cache-Control", "no-cache, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(vr.body)
}
