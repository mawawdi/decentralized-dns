package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/mawawdi/decentralized-dns/resolver/internal/cache"
	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
	"github.com/mawawdi/decentralized-dns/resolver/internal/config"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
	bttorrent "github.com/mawawdi/decentralized-dns/resolver/internal/torrent"
	"github.com/mawawdi/decentralized-dns/resolver/internal/zk"
)

// fakeChain is an in-memory ChainReader for handler tests.
type fakeChain struct {
	resolveCalls int
	lastSelector string
	records      map[string]chain.ResolveResult // key: name|type|selector
	domains      map[string]chain.Domain
	types        []string
}

func key2(name, typ, sel string) string { return name + "|" + typ + "|" + sel }

func (f *fakeChain) Resolve(_ context.Context, name, recordType, selector string) (*chain.ResolveResult, error) {
	f.resolveCalls++
	f.lastSelector = selector
	if res, ok := f.records[key2(name, recordType, selector)]; ok {
		return &res, nil
	}
	return &chain.ResolveResult{}, nil // exists=false, zero owner
}

func (f *fakeChain) GetDomain(_ context.Context, name string) (*chain.Domain, error) {
	d := f.domains[name]
	return &d, nil
}

func (f *fakeChain) ListRecords(_ context.Context, name string) ([]chain.Record, error) {
	var out []chain.Record
	for _, r := range f.records {
		out = append(out, r.Record)
	}
	return out, nil
}

func (f *fakeChain) ListTypes(_ context.Context) ([]string, error) { return f.types, nil }

func (f *fakeChain) ChainHead(_ context.Context) (uint64, error) { return 7, nil }

var owner = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

const (
	resourceInfoHash = "0123456789abcdef0123456789abcdef01234567"
	resourceSHA      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type fakeResourceFetcher struct {
	body     []byte
	err      error
	calls    int
	infoHash string
	sha      string
	peers    []string
}

func (f *fakeResourceFetcher) Fetch(_ context.Context, infoHash, sha string, peers []string) ([]byte, error) {
	f.calls++
	f.infoHash = infoHash
	f.sha = sha
	f.peers = append([]string(nil), peers...)
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte(nil), f.body...), nil
}

func seededFake(t *testing.T) *fakeChain {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ownerAddr := crypto.PubkeyToAddress(key.PublicKey)
	pubKey := crypto.FromECDSAPub(&key.PublicKey)
	owner = ownerAddr

	rec := chain.Record{
		Type: "A", Selector: "", FieldNames: []string{"address"},
		FieldVals: []string{"93.184.216.34"}, TTL: 3600, Generation: 1, Exists: true,
	}
	if rec.OwnerSig, err = pki.SignRecord("example", rec, key); err != nil {
		t.Fatal(err)
	}
	if rec.Commitment, err = zk.Commitment(pki.RecordMessage("example", rec)); err != nil {
		t.Fatal(err)
	}
	svc := chain.Record{
		Type: "SVC", Selector: "port=443&service=HTTP&transport=QUIC",
		FieldNames: []string{"target", "service", "transport", "port"},
		FieldVals:  []string{"web.example", "HTTP", "QUIC", "443"},
		TTL:        600, Generation: 1, Exists: true,
	}
	if svc.OwnerSig, err = pki.SignRecord("example", svc, key); err != nil {
		t.Fatal(err)
	}
	resource := chain.Record{
		Type: "ResourceRef", Selector: "",
		FieldNames: []string{"infoHash", "sha256", "contentType"},
		FieldVals:  []string{resourceInfoHash, resourceSHA, "text/html"},
		TTL:        120, Generation: 1, Exists: true,
	}
	if resource.OwnerSig, err = pki.SignRecord("example", resource, key); err != nil {
		t.Fatal(err)
	}
	// forged record: valid shape, signature from a different key
	forged := chain.Record{
		Type: "MX", Selector: "zone=forged", FieldNames: []string{"host", "priority"},
		FieldVals: []string{"evil.example", "10"}, TTL: 60, Generation: 1, Exists: true,
	}
	attacker, _ := crypto.GenerateKey()
	if forged.OwnerSig, err = pki.SignRecord("example", forged, attacker); err != nil {
		t.Fatal(err)
	}
	return &fakeChain{
		records: map[string]chain.ResolveResult{
			key2("example", "A", ""):             {Record: rec, Owner: ownerAddr, PubKey: pubKey},
			key2("example", "SVC", svc.Selector): {Record: svc, Owner: ownerAddr, PubKey: pubKey},
			key2("example", "ResourceRef", ""):   {Record: resource, Owner: ownerAddr, PubKey: pubKey},
			key2("example", "MX", "zone=forged"): {Record: forged, Owner: ownerAddr, PubKey: pubKey},
		},
		domains: map[string]chain.Domain{
			"example": {Owner: ownerAddr, PubKey: pubKey, Expiry: 1<<62 - 1, Generation: 1},
		},
		types: []string{"A", "AAAA", "MX", "SVC", "ResourceRef"},
	}
}

func newTestServer(t *testing.T, fc ChainReader, rps, burst int) *Server {
	t.Helper()
	c, err := cache.New[*chain.ResolveResult](64)
	if err != nil {
		t.Fatal(err)
	}
	id, err := pki.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "resolver.key"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg:      &config.Config{RateRPS: rps, RateBurst: burst},
		log:      slog.New(slog.DiscardHandler),
		chain:    fc,
		cache:    c,
		identity: id,
		mux:      http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// get performs a request and, for signed envelopes, verifies the resolver
// signature and unwraps the payload.
func get(t *testing.T, s *Server, url string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON from %s: %v\n%s", url, err, w.Body.String())
	}
	body := map[string]any{}
	if _, signed := raw["signature"]; signed {
		var env pki.Envelope
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if err := pki.VerifyEnvelope(&env); err != nil {
			t.Fatalf("%s: envelope verification failed: %v", url, err)
		}
		if env.Resolver != s.identity.PublicKeyHex() {
			t.Fatalf("%s: envelope signed by %s, want %s", url, env.Resolver, s.identity.PublicKeyHex())
		}
		if err := json.Unmarshal(env.Data, &body); err != nil {
			t.Fatal(err)
		}
		return w, body
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return w, body
}

func rawGet(t *testing.T, s *Server, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	return w
}

func TestResolveReadThroughAndCache(t *testing.T) {
	fc := seededFake(t)
	s := newTestServer(t, fc, 100, 100)

	w, body := get(t, s, "/resolve?name=example&type=A")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %v", w.Code, body)
	}
	if body["found"] != true || body["cached"] != false {
		t.Fatalf("first hit: %v", body)
	}
	rec := body["record"].(map[string]any)
	if rec["fieldValues"].([]any)[0] != "93.184.216.34" {
		t.Errorf("record = %v", rec)
	}
	if body["owner"] != owner.Hex() {
		t.Errorf("owner = %v", body["owner"])
	}
	if body["ownerSigVerified"] != true {
		t.Errorf("ownerSigVerified = %v, want true", body["ownerSigVerified"])
	}

	// second hit must come from cache
	_, body = get(t, s, "/resolve?name=example&type=A")
	if body["cached"] != true {
		t.Errorf("second hit not cached: %v", body)
	}
	if fc.resolveCalls != 1 {
		t.Errorf("resolveCalls = %d, want 1", fc.resolveCalls)
	}
}

// TestResolveZKProof: a committed record gets a verifiable Groth16 proof in
// the response (UC-6); an uncommitted record gets none; the proof is cached
// with the entry (proving cost paid once per TTL window).
func TestResolveZKProof(t *testing.T) {
	fc := seededFake(t)
	s := newTestServer(t, fc, 100, 100)

	_, body := get(t, s, "/resolve?name=example&type=A")
	proofHex, ok := body["zkProof"].(string)
	if !ok || len(proofHex) != 2+2*256 {
		t.Fatalf("zkProof = %v, want 256-byte hex", body["zkProof"])
	}
	calldata := common.FromHex(proofHex)
	proof, err := zk.ProofFromSolidityCalldata(calldata)
	if err != nil {
		t.Fatal(err)
	}
	rec := fc.records[key2("example", "A", "")].Record
	if err := zk.Verify(proof, rec.Commitment); err != nil {
		t.Fatalf("served proof does not verify: %v", err)
	}

	// cached hit serves the same proof without re-proving
	_, body = get(t, s, "/resolve?name=example&type=A")
	if body["cached"] != true || body["zkProof"] != proofHex {
		t.Errorf("cached hit lost the proof: cached=%v", body["cached"])
	}

	// record without a commitment carries no proof
	_, body = get(t, s, "/resolve?name=example&type=SVC&port=443&service=HTTP&transport=QUIC")
	if _, has := body["zkProof"]; has {
		t.Errorf("uncommitted record must not carry zkProof: %v", body["zkProof"])
	}
}

func TestResourceFetchServesSignedVerifiedBody(t *testing.T) {
	fc := seededFake(t)
	s := newTestServer(t, fc, 100, 100)
	payload := []byte("<!doctype html><title>Decentralized DNS</title>")
	fetcher := &fakeResourceFetcher{body: payload}
	s.resource = fetcher
	s.allowPeerHints = true // this test exercises peer-hint forwarding

	w := rawGet(t, s, "/resource?name=example&peer=127.0.0.1:42069&peer=127.0.0.1:42070")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != string(payload) {
		t.Fatalf("body = %q, want %q", w.Body.String(), payload)
	}
	if fetcher.calls != 1 || fetcher.infoHash != resourceInfoHash || fetcher.sha != resourceSHA {
		t.Fatalf("fetch args = calls:%d info:%q sha:%q", fetcher.calls, fetcher.infoHash, fetcher.sha)
	}
	if len(fetcher.peers) != 2 || fetcher.peers[0] != "127.0.0.1:42069" || fetcher.peers[1] != "127.0.0.1:42070" {
		t.Fatalf("peers = %v", fetcher.peers)
	}
	if w.Header().Get("Content-Type") != "text/html" {
		t.Fatalf("content-type = %q", w.Header().Get("Content-Type"))
	}
	if w.Header().Get("X-DDNS-OwnerSig-Verified") != "true" {
		t.Fatalf("owner sig header = %q", w.Header().Get("X-DDNS-OwnerSig-Verified"))
	}
	if w.Header().Get("X-DDNS-InfoHash") != resourceInfoHash || w.Header().Get("X-DDNS-SHA256") != resourceSHA {
		t.Fatalf("resource headers info=%q sha=%q", w.Header().Get("X-DDNS-InfoHash"), w.Header().Get("X-DDNS-SHA256"))
	}
	if w.Header().Get("Cache-Control") != "public, max-age=120" {
		t.Fatalf("cache-control = %q", w.Header().Get("Cache-Control"))
	}
	// The resolver signs a manifest binding the body to its provenance, not the
	// body alone, so none of the X-DDNS-* headers can be altered in transit.
	if err := pki.VerifyResourceSignature(
		w.Header().Get("X-DDNS-Resolver"),
		w.Header().Get("X-DDNS-Signature"),
		w.Header().Get("X-DDNS-Owner"),
		w.Header().Get("X-DDNS-PubKey"),
		resourceInfoHash, resourceSHA, "text/html", true, "",
		w.Body.Bytes(),
	); err != nil {
		t.Fatalf("resource provenance signature did not verify: %v", err)
	}

	// Tampering with any signed header must break verification.
	if err := pki.VerifyResourceSignature(
		w.Header().Get("X-DDNS-Resolver"),
		w.Header().Get("X-DDNS-Signature"),
		"0xdeadbeef", // forged owner
		w.Header().Get("X-DDNS-PubKey"),
		resourceInfoHash, resourceSHA, "text/html", true, "",
		w.Body.Bytes(),
	); err == nil {
		t.Fatal("tampered owner header must fail provenance verification")
	}
}

func TestResourceFetchRejectsTamperAndBadOwnerSignature(t *testing.T) {
	t.Run("hash mismatch", func(t *testing.T) {
		fc := seededFake(t)
		s := newTestServer(t, fc, 100, 100)
		s.resource = &fakeResourceFetcher{err: bttorrent.ErrHashMismatch}
		w := rawGet(t, s, "/resource?name=example")
		if w.Code != http.StatusBadGateway {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}
		var body errorBody
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Error != "resource_hash_mismatch" {
			t.Fatalf("error = %q", body.Error)
		}
	})

	t.Run("bad owner signature", func(t *testing.T) {
		fc := seededFake(t)
		res := fc.records[key2("example", "ResourceRef", "")]
		res.Record.OwnerSig = []byte{1, 2, 3}
		fc.records[key2("example", "ResourceRef", "")] = res
		fetcher := &fakeResourceFetcher{body: []byte("must not fetch")}
		s := newTestServer(t, fc, 100, 100)
		s.resource = fetcher
		w := rawGet(t, s, "/resource?name=example")
		if w.Code != http.StatusBadGateway {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}
		if fetcher.calls != 0 {
			t.Fatalf("fetch called despite bad owner signature")
		}
	})

	t.Run("engine disabled", func(t *testing.T) {
		s := newTestServer(t, seededFake(t), 100, 100)
		w := rawGet(t, s, "/resource?name=example")
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestResolveSelectorNormalization(t *testing.T) {
	fc := seededFake(t)
	s := newTestServer(t, fc, 100, 100)

	// explicit params, mixed case, unsorted -> canonical selector
	w, body := get(t, s, "/resolve?name=example&type=SVC&transport=quic&service=http&port=443")
	if w.Code != http.StatusOK || body["found"] != true {
		t.Fatalf("status=%d body=%v", w.Code, body)
	}
	if fc.lastSelector != "port=443&service=HTTP&transport=QUIC" {
		t.Errorf("selector sent to chain = %q", fc.lastSelector)
	}

	// raw selector string form works too
	_, body = get(t, s, "/resolve?name=example&type=SVC&selector=service%3Dhttp%26port%3D443%26transport%3Dquic")
	if body["found"] != true {
		t.Errorf("raw selector form: %v", body)
	}
}

func TestResolveTypedNoMatch(t *testing.T) {
	s := newTestServer(t, seededFake(t), 100, 100)
	w, body := get(t, s, "/resolve?name=example&type=AAAA")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if body["found"] != false || body["error"] != "no_match" {
		t.Errorf("body = %v", body)
	}
	if _, hasRecord := body["record"]; hasRecord {
		t.Error("no_match must not carry a record")
	}
}

func TestResolveForgedOwnerSig(t *testing.T) {
	s := newTestServer(t, seededFake(t), 100, 100)
	w, body := get(t, s, "/resolve?name=example&type=MX&selector=zone%3Dforged")
	if w.Code != http.StatusOK || body["found"] != true {
		t.Fatalf("status=%d body=%v", w.Code, body)
	}
	if body["ownerSigVerified"] != false {
		t.Errorf("forged record reported ownerSigVerified=%v, want false", body["ownerSigVerified"])
	}
}

func TestResolveValidation(t *testing.T) {
	s := newTestServer(t, seededFake(t), 100, 100)
	urls := []string{
		"/resolve",                                                // missing name+type
		"/resolve?name=UPPER&type=A",                              // bad name
		"/resolve?name=example&type=bad%20type",                   // bad type
		"/resolve?name=example&type=SVC&port=99999",               // bad port
		"/resolve?name=example&type=SVC&transport=SCTP",           // bad transport
		"/resolve?name=example&type=SVC&selector=port%3D1&port=2", // dup key
	}
	for _, u := range urls {
		w, body := get(t, s, u)
		if w.Code != http.StatusBadRequest || body["error"] != "invalid_query" {
			t.Errorf("%s: status=%d body=%v", u, w.Code, body)
		}
	}
}

func TestRateLimit429(t *testing.T) {
	s := newTestServer(t, seededFake(t), 1, 2) // 1 rps, burst 2

	codes := []int{}
	for range 4 {
		w, _ := get(t, s, "/resolve?name=example&type=A")
		codes = append(codes, w.Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK {
		t.Fatalf("burst should pass: %v", codes)
	}
	if codes[2] != http.StatusTooManyRequests || codes[3] != http.StatusTooManyRequests {
		t.Fatalf("expected 429s after burst: %v", codes)
	}

	// healthz is exempt from limiting
	w, _ := get(t, s, "/healthz")
	if w.Code == http.StatusTooManyRequests {
		t.Error("healthz must not be rate limited")
	}
}

func TestDomainEndpoint(t *testing.T) {
	s := newTestServer(t, seededFake(t), 100, 100)

	w, body := get(t, s, "/domains/example")
	if w.Code != http.StatusOK || body["active"] != true {
		t.Fatalf("status=%d body=%v", w.Code, body)
	}
	records := body["records"].([]any)
	if len(records) != 4 {
		t.Errorf("records = %v", body["records"])
	}
	foundResource := false
	for _, raw := range records {
		rec := raw.(map[string]any)
		if rec["type"] == "ResourceRef" {
			foundResource = true
		}
	}
	if !foundResource {
		t.Errorf("ResourceRef missing from records: %v", records)
	}

	w, body = get(t, s, "/domains/ghost")
	if w.Code != http.StatusNotFound || body["error"] != "not_registered" {
		t.Errorf("unregistered: status=%d body=%v", w.Code, body)
	}

	w, _ = get(t, s, "/domains/BAD!")
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad name: status=%d", w.Code)
	}
}

func TestTypesEndpoint(t *testing.T) {
	s := newTestServer(t, seededFake(t), 100, 100)
	w, body := get(t, s, "/types")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if len(body["types"].([]any)) != 5 {
		t.Errorf("types = %v", body["types"])
	}
}
