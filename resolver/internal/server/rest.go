package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
	"github.com/mawawdi/decentralized-dns/resolver/internal/query"
)

// chainCallTimeout bounds every chain read triggered by an HTTP request.
const chainCallTimeout = 10 * time.Second

// queryJSON echoes the normalized query back to the caller.
type queryJSON struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Selector string `json:"selector"`
}

// recordJSON is the wire form of a chain.Record, with binary fields as
// 0x-hex so clients can re-verify signatures and commitments byte-exactly.
type recordJSON struct {
	Type        string   `json:"type"`
	Selector    string   `json:"selector"`
	FieldNames  []string `json:"fieldNames"`
	FieldValues []string `json:"fieldValues"`
	TTL         uint32   `json:"ttl"`
	Generation  uint64   `json:"generation"`
	OwnerSig    string   `json:"ownerSig"`
	Commitment  string   `json:"commitment"`
}

func toRecordJSON(r chain.Record) *recordJSON {
	return &recordJSON{
		Type:        r.Type,
		Selector:    r.Selector,
		FieldNames:  r.FieldNames,
		FieldValues: r.FieldVals,
		TTL:         r.TTL,
		Generation:  r.Generation,
		OwnerSig:    hexutil.Encode(r.OwnerSig),
		Commitment:  hexutil.Encode(r.Commitment[:]),
	}
}

// resolveResponse is the REST answer envelope. A missing record is a typed
// "no match" (found=false, error=no_match) with HTTP 200: like NXDOMAIN it
// is a successful, authoritative denial.
type resolveResponse struct {
	Query            queryJSON   `json:"query"`
	Found            bool        `json:"found"`
	Error            string      `json:"error,omitempty"`
	Record           *recordJSON `json:"record,omitempty"`
	Owner            string      `json:"owner,omitempty"`
	PubKey           string      `json:"pubKey,omitempty"`
	OwnerSigVerified bool        `json:"ownerSigVerified"`
	ZKProof          string      `json:"zkProof,omitempty"`
	Cached           bool        `json:"cached"`
}

type domainResponse struct {
	Name       string        `json:"name"`
	Owner      string        `json:"owner"`
	PubKey     string        `json:"pubKey"`
	Expiry     uint64        `json:"expiry"`
	Generation uint64        `json:"generation"`
	Active     bool          `json:"active"`
	Records    []*recordJSON `json:"records"`
}

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: code, Message: msg})
}

// writeSigned wraps v in a resolver-signed envelope (HLD §3.3: every
// response is signed by the resolver's ed25519 identity).
func (s *Server) writeSigned(w http.ResponseWriter, status int, v any) {
	env, err := s.identity.SealEnvelope(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign_error", err.Error())
		return
	}
	writeJSON(w, status, env)
}

// rateLimited wraps a handler with the per-IP limiter.
func (s *Server) rateLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !s.limiter.allow(ip) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
			return
		}
		next(w, r)
	}
}

// parseResolveQuery turns ?name=&type=&selector=&port=&transport=&service=
// into a normalized query.Query. Explicit selector params merge with (and
// must not duplicate) keys from the raw selector string.
func parseResolveQuery(r *http.Request) (query.Query, error) {
	params := r.URL.Query()
	pairs, err := query.ParsePairs(params.Get("selector"))
	if err != nil {
		return query.Query{}, err
	}
	for _, k := range []string{"port", "transport", "service"} {
		if v := params.Get(k); v != "" {
			if _, dup := pairs[k]; dup {
				return query.Query{}, &dupSelectorError{key: k}
			}
			pairs[k] = v
		}
	}
	return query.New(params.Get("name"), params.Get("type"), pairs)
}

type dupSelectorError struct{ key string }

func (e *dupSelectorError) Error() string {
	return "selector key " + e.key + " given both in selector= and as a query param"
}

func (s *Server) resolveResponse(ctx context.Context, q query.Query) (resolveResponse, error) {
	res, err := s.HandleQuery(ctx, q)
	if err != nil {
		return resolveResponse{}, err
	}
	resp := resolveResponse{
		Query:  queryJSON{Name: q.Name, Type: q.Type, Selector: q.Selector},
		Cached: res.Cached,
	}
	if !res.Found() {
		resp.Error = "no_match"
		return resp, nil
	}
	resp.Found = true
	resp.Record = toRecordJSON(res.Result.Record)
	resp.Owner = res.Result.Owner.Hex()
	resp.PubKey = hexutil.Encode(res.Result.PubKey)
	resp.OwnerSigVerified = res.Result.OwnerSigValid
	if len(res.Result.ZKProof) > 0 {
		resp.ZKProof = hexutil.Encode(res.Result.ZKProof)
	}
	return resp, nil
}

// handleResolve serves GET /resolve (HLD §3.2 query API, UC-4/UC-5).
func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	q, err := parseResolveQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), chainCallTimeout)
	defer cancel()

	resp, err := s.resolveResponse(ctx, q)
	if err != nil {
		writeError(w, http.StatusBadGateway, "chain_error", err.Error())
		return
	}
	s.writeSigned(w, http.StatusOK, resp)
}

// handleDomain serves GET /domains/{name}: raw domain state + live records.
func (s *Server) handleDomain(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := query.ValidateName(name); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), chainCallTimeout)
	defer cancel()

	dom, err := s.chain.GetDomain(ctx, name)
	if err != nil {
		writeError(w, http.StatusBadGateway, "chain_error", err.Error())
		return
	}
	if dom.Owner == (common.Address{}) {
		writeError(w, http.StatusNotFound, "not_registered", "domain is not registered")
		return
	}
	active := dom.Expiry > uint64(time.Now().Unix())
	resp := domainResponse{
		Name:       name,
		Owner:      dom.Owner.Hex(),
		PubKey:     hexutil.Encode(dom.PubKey),
		Expiry:     dom.Expiry,
		Generation: dom.Generation,
		Active:     active,
		Records:    []*recordJSON{},
	}
	if active {
		records, err := s.chain.ListRecords(ctx, name)
		if err != nil {
			writeError(w, http.StatusBadGateway, "chain_error", err.Error())
			return
		}
		for _, rec := range records {
			resp.Records = append(resp.Records, toRecordJSON(rec))
		}
	}
	s.writeSigned(w, http.StatusOK, resp)
}

// handleTypes serves GET /types: all declared record types.
func (s *Server) handleTypes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), chainCallTimeout)
	defer cancel()

	types, err := s.chain.ListTypes(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "chain_error", err.Error())
		return
	}
	s.writeSigned(w, http.StatusOK, map[string][]string{"types": types})
}
