package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/devCana/decentralized-dns/resolver/internal/contenttype"
	"github.com/devCana/decentralized-dns/resolver/internal/pki"
	"github.com/devCana/decentralized-dns/resolver/internal/query"
	bttorrent "github.com/devCana/decentralized-dns/resolver/internal/torrent"
)

const resourceFetchTimeout = 10 * time.Second

// webSandboxCSP is applied to every response that carries owner-controlled
// bytes onto the browser (/web and /resource). Without it, every
// decentralized "site" resolved through this resolver would render under one
// real origin — the resolver's own scheme+host+port — since /web/<name> is
// just a path, not a distinct hostname the way real DNS gives each domain its
// own origin. A malicious owner's script would then share that origin with
// every *other* name resolved through the same resolver: able to read/write
// their localStorage, IndexedDB and cookies, or register a service worker
// that hijacks future requests to any /web/* path. The CSP `sandbox`
// directive (with neither allow-same-origin nor allow-top-navigation) forces
// each response into a fresh, opaque origin instead — browsers honour it even
// for a top-level navigation, not just an iframe — while allow-scripts and
// allow-forms keep the served site itself fully interactive.
const webSandboxCSP = "sandbox allow-scripts allow-forms; base-uri 'none'"

// ResourceFetcher is the torrent fetch API needed by the REST resource flow.
type ResourceFetcher interface {
	Fetch(ctx context.Context, infoHashHex, expectedSHAHex string, peers []string) ([]byte, error)
}

func parseResourceQuery(r *http.Request) (query.Query, error) {
	params := r.URL.Query()
	recordType := params.Get("type")
	if recordType == "" {
		recordType = "ResourceRef"
	}
	if recordType != "ResourceRef" {
		return query.Query{}, fmt.Errorf("resource endpoint only resolves ResourceRef records")
	}
	pairs, err := query.ParsePairs(params.Get("selector"))
	if err != nil {
		return query.Query{}, err
	}
	return query.New(params.Get("name"), recordType, pairs)
}

// verifiedResource is the fully checked payload of a ResourceRef: the bytes,
// every provenance field, and the content-type validation verdict.
type verifiedResource struct {
	body        []byte
	owner       string
	pubKeyHex   string
	infoHash    string
	sha         string
	contentType string
	zkHex       string
	validation  contenttype.Result
	ttl         uint32
}

// resourceError carries an HTTP status + machine code for a failed fetch.
type resourceError struct {
	status int
	code   string
	msg    string
}

// fetchVerifiedResource runs the full ResourceRef pipeline shared by the
// /resource API and the /web gateway: resolve + owner-signature check via
// HandleQuery, pull the bytes from BitTorrent (which re-hashes against the
// on-chain sha256), then validate the served content type locally (FS §2.2).
// It returns a nil *resourceError on success.
func (s *Server) fetchVerifiedResource(ctx context.Context, q query.Query, peers []string) (*verifiedResource, *resourceError) {
	if s.resource == nil {
		return nil, &resourceError{http.StatusServiceUnavailable, "resource_engine_unavailable", "resource fetching is not enabled"}
	}
	res, err := s.HandleQuery(ctx, q)
	if err != nil {
		return nil, &resourceError{http.StatusBadGateway, "chain_error", err.Error()}
	}
	if !res.Found() {
		return nil, &resourceError{http.StatusNotFound, "no_match", "ResourceRef record was not found"}
	}
	if !res.Result.OwnerSigValid {
		return nil, &resourceError{http.StatusBadGateway, "owner_signature_invalid", "ResourceRef owner signature failed verification"}
	}

	rec := res.Result.Record
	infoHash, ok := rec.Field("infoHash")
	if !ok || strings.TrimSpace(infoHash) == "" {
		return nil, &resourceError{http.StatusBadGateway, "bad_resource_ref", "ResourceRef is missing infoHash"}
	}
	sha, ok := rec.Field("sha256")
	if !ok || strings.TrimSpace(sha) == "" {
		return nil, &resourceError{http.StatusBadGateway, "bad_resource_ref", "ResourceRef is missing sha256"}
	}
	contentType, ok := rec.Field("contentType")
	if !ok || strings.TrimSpace(contentType) == "" {
		contentType = "application/octet-stream"
	}
	if strings.ContainsAny(contentType, "\r\n") {
		return nil, &resourceError{http.StatusBadGateway, "bad_resource_ref", "ResourceRef contentType is invalid"}
	}

	// Bound concurrent fetches: each buffers up to MaxFetchBytes in RAM, so an
	// unbounded fan-out is a memory-exhaustion DoS even within the rate limit.
	if s.resourceSem != nil {
		select {
		case s.resourceSem <- struct{}{}:
			defer func() { <-s.resourceSem }()
		case <-ctx.Done():
			return nil, &resourceError{http.StatusServiceUnavailable, "resource_busy", "resolver is busy serving resources; retry shortly"}
		}
	}

	body, err := s.resource.Fetch(ctx, infoHash, sha, peers)
	if err != nil {
		switch {
		case errors.Is(err, bttorrent.ErrHashMismatch):
			return nil, &resourceError{http.StatusBadGateway, "resource_hash_mismatch", "torrent payload did not match on-chain sha256"}
		case errors.Is(err, bttorrent.ErrTooLarge):
			return nil, &resourceError{http.StatusBadGateway, "resource_too_large", err.Error()}
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			return nil, &resourceError{http.StatusGatewayTimeout, "resource_timeout", err.Error()}
		default:
			return nil, &resourceError{http.StatusBadGateway, "resource_fetch_failed", err.Error()}
		}
	}

	// Resource Type Validation (FS §2.2, HLD open issue #3): sniff the verified
	// bytes locally and confirm they are consistent with the declared media
	// type. By default a mismatch is flagged (header + log); in strict mode
	// (ENFORCE_CONTENT_TYPE) the resolver refuses to serve it.
	validation := contenttype.Validate(contentType, body)
	if !validation.OK {
		s.log.Warn("resource content-type mismatch", "name", q.Name,
			"declared", validation.Declared, "detected", validation.Detected)
		if s.enforceType {
			return nil, &resourceError{http.StatusUnprocessableEntity, "content_type_mismatch", validation.Reason}
		}
	}

	zkHex := ""
	if len(res.Result.ZKProof) > 0 {
		zkHex = hexutil.Encode(res.Result.ZKProof)
	}
	return &verifiedResource{
		body:        body,
		owner:       res.Result.Owner.Hex(),
		pubKeyHex:   hexutil.Encode(res.Result.PubKey),
		infoHash:    infoHash,
		sha:         sha,
		contentType: contentType,
		zkHex:       zkHex,
		validation:  validation,
		ttl:         rec.TTL,
	}, nil
}

// handleResource serves GET /resource?name=&selector=&peer=. It resolves a
// ResourceRef, verifies it end-to-end, and returns the exact verified bytes
// with a resolver signature binding the body to all provenance headers (so a
// man-in-the-middle cannot rewrite any of them); ddns-fetch re-checks it all.
func (s *Server) handleResource(w http.ResponseWriter, r *http.Request) {
	q, err := parseResourceQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), resourceFetchTimeout)
	defer cancel()

	vr, rerr := s.fetchVerifiedResource(ctx, q, s.resourcePeers(r))
	if rerr != nil {
		writeError(w, rerr.status, rerr.code, rerr.msg)
		return
	}

	// Sign a manifest binding the body to all provenance fields.
	sig := hexutil.Encode(s.identity.Sign(
		pki.ResourceManifest(vr.owner, vr.pubKeyHex, vr.infoHash, vr.sha, vr.contentType, true, vr.zkHex, vr.body),
	))
	h := w.Header()
	h.Set("Content-Type", vr.contentType)
	h.Set("X-Content-Type-Options", "nosniff") // honour the owner-declared type exactly
	h.Set("Content-Security-Policy", webSandboxCSP)
	h.Set("X-DDNS-Resolver", s.identity.PublicKeyHex())
	h.Set("X-DDNS-Sig-Scheme", "ddns-resource-v1")
	h.Set("X-DDNS-Signature", sig)
	h.Set("X-DDNS-Owner", vr.owner)
	h.Set("X-DDNS-PubKey", vr.pubKeyHex)
	h.Set("X-DDNS-InfoHash", vr.infoHash)
	h.Set("X-DDNS-SHA256", vr.sha)
	h.Set("X-DDNS-OwnerSig-Verified", "true")
	h.Set("X-DDNS-Content-Validation", validationStatus(vr.validation.OK))
	h.Set("X-DDNS-Detected-Type", vr.validation.Detected)
	if vr.zkHex != "" {
		h.Set("X-DDNS-ZKProof", vr.zkHex)
	}
	if vr.ttl > 0 {
		h.Set("Cache-Control", fmt.Sprintf("public, max-age=%d", vr.ttl))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(vr.body)
}

// validationStatus maps a content-type verdict to a stable header token.
func validationStatus(ok bool) string {
	if ok {
		return "ok"
	}
	return "mismatch"
}

// resourcePeers returns the client-supplied ?peer= hints, but only when the
// operator has explicitly enabled them (ALLOW_PEER_HINTS). They are forwarded
// to the torrent engine as trusted dial targets, so accepting arbitrary
// host:port from unauthenticated callers would be an SSRF vector; by default
// the resolver relies on DHT discovery instead. Even when enabled, the list is
// length-capped and each entry must parse as host:port.
func (s *Server) resourcePeers(r *http.Request) []string {
	const maxPeers = 16
	var out []string
	for _, p := range r.URL.Query()["peer"] {
		host, _, err := net.SplitHostPort(p)
		if err != nil {
			continue
		}
		if !s.allowPeerHints && !isLoopbackHost(host) {
			continue
		}
		out = append(out, p)
		if len(out) >= maxPeers {
			break
		}
	}
	return out
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return strings.EqualFold(host, "localhost")
}
