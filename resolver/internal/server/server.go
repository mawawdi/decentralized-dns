// Package server hosts the ResolverServer orchestrator (HLD §4.1.2): it
// boots subsystems, wires them together, and owns the shared config.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/mawawdi/decentralized-dns/resolver/internal/cache"
	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
	"github.com/mawawdi/decentralized-dns/resolver/internal/config"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
	bttorrent "github.com/mawawdi/decentralized-dns/resolver/internal/torrent"
)

// eventPollInterval is how often the resolver polls the chain for record
// events driving proactive cache invalidation.
const eventPollInterval = 2 * time.Second

// Server is the top-level resolver orchestrator.
type Server struct {
	cfg            *config.Config
	log            *slog.Logger
	chain          ChainReader
	events         *chain.Client // event watcher; nil in handler tests
	cache          *cache.TTLCache[*chain.ResolveResult]
	bt             *bttorrent.Engine
	resource       ResourceFetcher
	identity       *pki.Identity
	limiter        *ipLimiter
	allowPeerHints bool
	enforceType    bool
	startTime      time.Time
	resourceSem    chan struct{} // bounds concurrent (memory-heavy) resource fetches
	mux            *http.ServeMux
}

// maxConcurrentResourceFetches caps how many resource downloads buffer at once;
// each can hold up to MaxFetchBytes in RAM, so this bounds memory under load.
const maxConcurrentResourceFetches = 8

// New validates config and connects the subsystems.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Server, error) {
	if !common.IsHexAddress(cfg.ContractAddress) {
		return nil, fmt.Errorf("CONTRACT_ADDRESS %q is not a hex address", cfg.ContractAddress)
	}
	if !common.IsHexAddress(cfg.RegistryAddress) {
		return nil, fmt.Errorf("REGISTRY_ADDRESS %q is not a hex address", cfg.RegistryAddress)
	}
	chainClient, err := chain.Dial(ctx, cfg.RPCURL,
		common.HexToAddress(cfg.ContractAddress),
		common.HexToAddress(cfg.RegistryAddress), log)
	if err != nil {
		return nil, err
	}
	ttlCache, err := cache.New[*chain.ResolveResult](cfg.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("cache: %w", err)
	}
	identity, err := pki.LoadOrCreateIdentity(cfg.KeystorePath)
	if err != nil {
		return nil, fmt.Errorf("resolver identity: %w", err)
	}
	log.Info("resolver identity", "pubKey", identity.PublicKeyHex())
	bt, err := bttorrent.New(bttorrent.Config{DataDir: filepath.Join(cfg.DataDir, "torrent"), ListenPort: cfg.BTListenPort, Logger: log})
	if err != nil {
		chainClient.Close()
		return nil, err
	}

	s := &Server{cfg: cfg, log: log, chain: chainClient, events: chainClient, cache: ttlCache, bt: bt, resource: bt, identity: identity, allowPeerHints: cfg.AllowPeerHints, enforceType: cfg.EnforceType, startTime: time.Now(), mux: http.NewServeMux()}
	s.registerRoutes()
	return s, nil
}

// registerRoutes mounts the REST QueryAPI (HLD §4.1.2). The health probe
// is exempt from rate limiting so orchestrators can poll freely.
func (s *Server) registerRoutes() {
	s.limiter = newIPLimiter(s.cfg.RateRPS, s.cfg.RateBurst)
	s.resourceSem = make(chan struct{}, maxConcurrentResourceFetches)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /resolve", s.rateLimited(s.handleResolve))
	s.mux.HandleFunc("GET /resource", s.rateLimited(s.handleResource))
	s.mux.HandleFunc("GET /web/{name}", s.rateLimited(s.handleWeb))
	s.mux.HandleFunc("GET /domains/{name}", s.rateLimited(s.handleDomain))
	s.mux.HandleFunc("GET /types", s.rateLimited(s.handleTypes))
	// Operator console (HLD §4.3): rate-limited so /admin/stats can't be used to
	// hammer the chain RPC, but no auth — bind it to a trusted network.
	s.mux.HandleFunc("GET /admin", s.rateLimited(s.handleAdmin))
	s.mux.HandleFunc("GET /admin/stats", s.rateLimited(s.handleAdminStats))
	if s.cfg.EnableShowcase {
		s.registerShowcaseRoutes()
	}
}

// Chain exposes the blockchain reader to sibling subsystems.
func (s *Server) Chain() ChainReader { return s.chain }

// Cache exposes the TTL cache (REST handlers, admin dashboard).
func (s *Server) Cache() *cache.TTLCache[*chain.ResolveResult] { return s.cache }

// Handler returns the root HTTP handler (REST API mounts onto it later).
func (s *Server) Handler() http.Handler { return s.mux }

// Mux exposes the route registry for subsystems (REST API, admin).
func (s *Server) Mux() *http.ServeMux { return s.mux }

// Run serves HTTP until ctx is cancelled, then shuts down gracefully. It
// also runs the event watcher feeding push invalidation into the cache.
func (s *Server) Run(ctx context.Context) error {
	defer func() {
		if s.bt != nil {
			s.bt.Close()
		}
	}()
	udpConn := s.listenUDP(ctx)
	if udpConn != nil {
		defer udpConn.Close()
	}
	httpSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.cfg.RESTPort),
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		err := s.events.WatchRecordEvents(ctx, eventPollInterval, func(ev chain.RecordEvent) {
			s.log.Debug("invalidating", "kind", ev.Kind, "name", ev.Name)
			s.cache.HandleEvent(ev)
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			s.log.Warn("event watcher stopped", "err", err)
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("REST listening", "port", s.cfg.RESTPort)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		s.events.Close()
		return nil
	case err := <-errCh:
		// The HTTP server died on its own; close the chain client so the event
		// watcher goroutine unblocks instead of leaking.
		s.events.Close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	head, err := s.chain.ChainHead(ctx)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "degraded", "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "chainHead": head})
}
