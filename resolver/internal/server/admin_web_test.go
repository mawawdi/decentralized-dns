package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAdminStatsJSON(t *testing.T) {
	fc := seededFake(t)
	s := newTestServer(t, fc, 100, 100)

	// Drive one cache miss + hit so the counters are non-trivial.
	get(t, s, "/resolve?name=example&type=A")
	get(t, s, "/resolve?name=example&type=A")

	w := rawGet(t, s, "/admin/stats")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var st adminStats
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, w.Body.String())
	}
	if st.Resolver != s.identity.PublicKeyHex() {
		t.Errorf("resolver = %q, want %q", st.Resolver, s.identity.PublicKeyHex())
	}
	if !st.ChainOK || st.ChainHead != 7 {
		t.Errorf("chain head = %d ok=%v, want 7 true", st.ChainHead, st.ChainOK)
	}
	if st.Cache.Hits == 0 || st.Cache.Misses == 0 {
		t.Errorf("cache counters not populated: %+v", st.Cache)
	}
}

func TestAdminDashboardHTML(t *testing.T) {
	fc := seededFake(t)
	s := newTestServer(t, fc, 100, 100)

	w := rawGet(t, s, "/admin")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	body := w.Body.String()
	for _, want := range []string{"Resolver Console", s.identity.PublicKeyHex(), "TTL cache", "BitTorrent swarm"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard HTML missing %q", want)
		}
	}
}

func TestWebGatewayServesVerifiedSite(t *testing.T) {
	fc := seededFake(t)
	s := newTestServer(t, fc, 100, 100)
	page := []byte("<!doctype html><title>site</title><h1>decentralized</h1>")
	s.resource = &fakeResourceFetcher{body: page}

	// A website ResourceRef is conventionally registered under service=HTTP,
	// which is exactly the selector /web defaults to. Publish it there.
	fc.records[key2("example", "ResourceRef", "service=HTTP")] = fc.records[key2("example", "ResourceRef", "")]

	w := rawGet(t, s, "/web/example")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != string(page) {
		t.Fatalf("body = %q", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("content-type = %q", ct)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff header")
	}
	if w.Header().Get("X-DDNS-Content-Validation") != "ok" {
		t.Errorf("validation header = %q", w.Header().Get("X-DDNS-Content-Validation"))
	}
	// Served sites must be sandboxed into their own opaque origin so one
	// decentralized name can never reach into another's storage/cookies via
	// the resolver's shared real origin (see webSandboxCSP).
	if csp := w.Header().Get("Content-Security-Policy"); csp != webSandboxCSP {
		t.Errorf("CSP = %q, want %q", csp, webSandboxCSP)
	}
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "allow-same-origin") {
		t.Error("CSP must not grant allow-same-origin: that would defeat the per-site sandbox")
	}
}

func TestResourceContentTypeMismatchFlagged(t *testing.T) {
	fc := seededFake(t)
	s := newTestServer(t, fc, 100, 100)
	// The ResourceRef declares text/html, but serve PNG bytes instead.
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	s.resource = &fakeResourceFetcher{body: png}

	// Default (advisory) mode: still served, but flagged as a mismatch.
	w := rawGet(t, s, "/resource?name=example")
	if w.Code != http.StatusOK {
		t.Fatalf("advisory mode status = %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-DDNS-Content-Validation") != "mismatch" {
		t.Errorf("validation header = %q, want mismatch", w.Header().Get("X-DDNS-Content-Validation"))
	}

	// Strict mode: refuse to serve the mismatched file.
	s.enforceType = true
	w = rawGet(t, s, "/resource?name=example")
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("strict mode status = %d, want 422\n%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "content_type_mismatch") {
		t.Errorf("missing error code: %s", w.Body.String())
	}
}

func TestResourceEndpointSandboxed(t *testing.T) {
	fc := seededFake(t)
	s := newTestServer(t, fc, 100, 100)
	s.resource = &fakeResourceFetcher{body: []byte("hello")}

	w := rawGet(t, s, "/resource?name=example")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	// A browser pointed directly at /resource must get the same opaque-origin
	// sandbox as /web — a mismatched or missing declared content type is not
	// the only way owner-controlled bytes reach a browser under this origin.
	if csp := w.Header().Get("Content-Security-Policy"); csp != webSandboxCSP {
		t.Errorf("CSP = %q, want %q", csp, webSandboxCSP)
	}
}
