// Interactive showcase UI (opt-in via ENABLE_SHOWCASE=true): a click-through
// demo of every feature in this project — resolve/verify, registration,
// record management, domain transfers, resource publishing, incentives, and
// an attack lab that tries to break the system live and shows it getting caught.
package server

import (
	"context"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
	"github.com/mawawdi/decentralized-dns/resolver/internal/zk"
)

//go:embed showcase_assets
var showcaseAssetsFS embed.FS

// registerShowcaseRoutes mounts /showcase/* — only called when
// cfg.EnableShowcase is true (see registerRoutes in server.go).
func (s *Server) registerShowcaseRoutes() {
	sub, err := fs.Sub(showcaseAssetsFS, "showcase_assets")
	if err != nil {
		panic("showcase: embedded assets: " + err.Error())
	}
	fileServer := http.FileServerFS(sub)

	s.mux.HandleFunc("GET /showcase", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/showcase/", http.StatusFound)
	})
	s.mux.Handle("GET /showcase/", http.StripPrefix("/showcase/", fileServer))
	s.mux.HandleFunc("GET /showcase/config", s.handleShowcaseConfig)
	s.mux.HandleFunc("POST /showcase/api/commit", s.handleShowcaseCommit)
	s.mux.HandleFunc("POST /showcase/api/publish", s.handleShowcasePublish)
	s.mux.HandleFunc("POST /showcase/api/invalidate", s.handleShowcaseInvalidate)
	s.mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	s.log.Info("showcase UI enabled at /showcase/")
}

// showcaseConfigResponse provides contract addresses and RPC configuration
// to the browser frontend.
type showcaseConfigResponse struct {
	NamespaceDApp        string `json:"namespaceDApp"`
	RecordSchemaRegistry string `json:"recordSchemaRegistry"`
	ResolverRegistry     string `json:"resolverRegistry,omitempty"`
	ResolverIncentives   string `json:"resolverIncentives,omitempty"`
	RPCURL               string `json:"rpcUrl"`
	RestBase             string `json:"restBase"`
}

func (s *Server) handleShowcaseConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, showcaseConfigResponse{
		NamespaceDApp:        s.cfg.ContractAddress,
		RecordSchemaRegistry: s.cfg.RegistryAddress,
		ResolverRegistry:     s.cfg.ResolverRegistryAddress,
		ResolverIncentives:   s.cfg.ResolverIncentivesAddress,
		RPCURL:               s.cfg.RPCURL,
		RestBase:             "",
	})
}

// commitRequest mirrors the fields pki.RecordMessage needs for the showcase
// UI to get a real MiMC commitment without reimplementing MiMC in JavaScript.
type commitRequest struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Selector    string   `json:"selector"`
	TTL         uint32   `json:"ttl"`
	Generation  uint64   `json:"generation"`
	FieldNames  []string `json:"fieldNames"`
	FieldValues []string `json:"fieldValues"`
}

func (s *Server) handleShowcaseCommit(w http.ResponseWriter, r *http.Request) {
	var req commitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if len(req.FieldNames) != len(req.FieldValues) {
		writeError(w, http.StatusBadRequest, "field_mismatch", "fieldNames/fieldValues length mismatch")
		return
	}
	rec := chain.Record{
		Type: req.Type, Selector: req.Selector,
		FieldNames: req.FieldNames, FieldVals: req.FieldValues,
		TTL: req.TTL, Generation: req.Generation,
	}
	msg := pki.RecordMessage(req.Name, rec)
	commitment, err := zk.Commitment(msg)
	if err != nil {
		writeError(w, http.StatusBadRequest, "commitment_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"commitment": "0x" + hex.EncodeToString(commitment[:])})
}

var showcaseUnsafeFilenameChars = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

type publishRequest struct {
	Name        string `json:"name"`
	Selector    string `json:"selector"`
	ContentType string `json:"contentType"`
	Body        string `json:"body"`
}

type publishResponse struct {
	InfoHash string `json:"infoHash"`
	SHA256   string `json:"sha256"`
}

func (s *Server) handleShowcasePublish(w http.ResponseWriter, r *http.Request) {
	if s.bt == nil {
		writeError(w, http.StatusServiceUnavailable, "resource_engine_unavailable", "BitTorrent engine is not enabled")
		return
	}
	var req publishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.Name == "" || req.Body == "" {
		writeError(w, http.StatusBadRequest, "missing_fields", "name and body are required")
		return
	}
	dir := filepath.Join(s.cfg.DataDir, "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
		return
	}
	safeName := showcaseUnsafeFilenameChars.ReplaceAllString(req.Name+"-"+req.Selector, "_")
	path := filepath.Join(dir, fmt.Sprintf("%s-%d.html", safeName, time.Now().UnixNano()))
	if err := os.WriteFile(path, []byte(req.Body), 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	infoHash, sha, err := s.bt.SeedFile(ctx, path)
	if err != nil {
		writeError(w, http.StatusBadGateway, "seed_failed", err.Error())
		return
	}
	s.cache.InvalidateName(req.Name)
	writeJSON(w, http.StatusOK, publishResponse{InfoHash: infoHash, SHA256: sha})
}

func (s *Server) handleShowcaseInvalidate(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name != "" {
		s.cache.InvalidateName(name)
	} else {
		s.cache.Flush()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
