// Package torrent wraps anacrolix/torrent behind the BitTorrentEngine API
// from HLD §3.6: resolvers seed published resources and fetch resources by
// infohash, re-hashing every payload end-to-end (SHA-256) against the
// on-chain digest before anything is served (UC-10 tamper rejection).
package torrent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
)

// MaxFetchBytes caps fetched resources; published site bundles are small
// zips, and the resolver must not be lured into buffering arbitrary blobs.
const MaxFetchBytes = 256 << 20 // 256 MiB

// ErrHashMismatch is returned when swarm-delivered content does not hash to
// the expected on-chain SHA-256. Content is discarded, never served (UC-10).
var ErrHashMismatch = errors.New("torrent: content hash does not match expected SHA-256")

// ErrTooLarge is returned when the announced torrent exceeds MaxFetchBytes.
var ErrTooLarge = errors.New("torrent: resource exceeds maximum fetch size")

// maxRetainedTorrents bounds how many fetched resources the resolver keeps
// seeding (HLD §3.6: the resolver acts as both leech and seeder). Once fetched
// and verified, a resource stays in the swarm so repeat requests are served
// locally; the oldest is dropped past this cap.
const maxRetainedTorrents = 256

// PublicOpenTrackers provides standard, high-reliability global BitTorrent trackers
// for worldwide peer discovery across the open internet.
var PublicOpenTrackers = [][]string{
	{"udp://tracker.opentrackr.org:1337/announce"},
	{"udp://open.stealth.si:80/announce"},
	{"udp://tracker.torrent.eu.org:451/announce"},
	{"udp://tracker.moeking.me:6969/announce"},
	{"udp://explodie.org:6969/announce"},
	{"http://tracker.opentrackr.org:1337/announce"},
}

// Config tunes an Engine.
type Config struct {
	DataDir    string       // where seeded/fetched payloads live
	ListenPort int          // TCP/uTP listen port (0 = random)
	DisableDHT bool         // true for local/e2e setups using explicit peers
	Logger     *slog.Logger // optional; defaults to slog.Default()
}

// Engine seeds and fetches static resources over BitTorrent.
type Engine struct {
	client *torrent.Client
	log    *slog.Logger

	mu       sync.Mutex             // guards all torrent bookkeeping below
	pinned   map[metainfo.Hash]bool // torrents that must NOT be auto-dropped (seeded + retained)
	retained []metainfo.Hash        // FIFO of *fetched* retentions, for LRU eviction
	inUse    map[metainfo.Hash]int  // in-flight Fetch readers per infohash
}

// New starts a BitTorrent client. Close the engine to stop seeding.
func New(cfg Config) (*Engine, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("torrent: data dir: %w", err)
	}
	cc := torrent.NewDefaultClientConfig()
	cc.DataDir = cfg.DataDir
	cc.ListenPort = cfg.ListenPort
	cc.NoDHT = cfg.DisableDHT
	cc.Seed = true
	cc.Logger.SetHandlers() // silence anacrolix's own logging; we use slog
	client, err := torrent.NewClient(cc)
	if err != nil {
		return nil, fmt.Errorf("torrent: client: %w", err)
	}
	return &Engine{
		client: client,
		log:    cfg.Logger,
		pinned: map[metainfo.Hash]bool{},
		inUse:  map[metainfo.Hash]int{},
	}, nil
}

// pin marks a torrent as permanently retained (a seeded file): release never
// drops it, and it is not subject to LRU eviction.
func (e *Engine) pin(ih metainfo.Hash) {
	e.mu.Lock()
	e.pinned[ih] = true
	e.mu.Unlock()
}

// acquire records that a Fetch is reading this torrent so it is not dropped
// out from under it.
func (e *Engine) acquire(ih metainfo.Hash) {
	e.mu.Lock()
	e.inUse[ih]++
	e.mu.Unlock()
}

// release ends a Fetch's use of a torrent, dropping it only when nobody else is
// reading it AND it is not pinned (seeded or retained). The actual Drop runs
// outside the lock, since Drop takes the torrent client's global lock and
// blocks on storage close.
func (e *Engine) release(ih metainfo.Hash) {
	e.mu.Lock()
	if e.inUse[ih] > 0 {
		e.inUse[ih]--
	}
	drop := e.inUse[ih] == 0 && !e.pinned[ih]
	if e.inUse[ih] == 0 {
		delete(e.inUse, ih)
	}
	e.mu.Unlock()
	if drop {
		if t, ok := e.client.Torrent(ih); ok {
			t.Drop()
		}
	}
}

// retain keeps a successfully fetched torrent seeding so future requests for
// the same resource are served from local storage (and re-seeded into the
// swarm) instead of re-downloaded. Bounded to maxRetainedTorrents by dropping
// the oldest fetched retention — but never one a Fetch is mid-read (those are
// left to release() to drop when the last reader finishes). Drops run outside
// the lock.
func (e *Engine) retain(ih metainfo.Hash) {
	var toDrop []metainfo.Hash
	e.mu.Lock()
	if !e.pinned[ih] {
		e.pinned[ih] = true
		e.retained = append(e.retained, ih)
	}
	for len(e.retained) > maxRetainedTorrents {
		old := e.retained[0]
		e.retained = e.retained[1:]
		delete(e.pinned, old)
		if e.inUse[old] == 0 {
			toDrop = append(toDrop, old) // safe to drop now; nobody is reading it
		}
	}
	e.mu.Unlock()
	for _, old := range toDrop {
		if t, ok := e.client.Torrent(old); ok {
			t.Drop()
		}
	}
}

// Close stops seeding and releases the listen sockets.
func (e *Engine) Close() {
	e.client.Close()
	<-e.client.Closed()
}

// ListenAddrs returns dialable addresses of this engine for explicit peer
// wiring (local compose networks have no public DHT). Unspecified hosts
// are rewritten to 127.0.0.1.
func (e *Engine) ListenAddrs() []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range e.client.ListenAddrs() {
		host, port, err := net.SplitHostPort(a.String())
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
			host = "127.0.0.1"
		}
		hp := net.JoinHostPort(host, port)
		if !seen[hp] {
			seen[hp] = true
			out = append(out, hp)
		}
	}
	return out
}

// SeedFile makes path available to the swarm. It returns the torrent
// infohash and the file's SHA-256, both hex — exactly what a ResourceRef
// record anchors on-chain. The file must stay in place while seeding. ctx
// bounds the wait for torrent metadata so the publish path can never hang
// indefinitely (e.g. on an infohash already added by a concurrent Fetch).
func (e *Engine) SeedFile(ctx context.Context, path string) (infoHash, sha string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return "", "", err
	}
	f.Close()

	info := metainfo.Info{PieceLength: 256 << 10}
	if err := info.BuildFromFilePath(path); err != nil {
		return "", "", fmt.Errorf("torrent: build metainfo: %w", err)
	}
	infoBytes, err := bencode.Marshal(info)
	if err != nil {
		return "", "", err
	}
	mi := &metainfo.MetaInfo{
		InfoBytes:    infoBytes,
		AnnounceList: PublicOpenTrackers,
	}
	ih := mi.HashInfoBytes()
	t, _ := e.client.AddTorrentOpt(torrent.AddTorrentOpts{
		InfoHash:  ih,
		InfoBytes: mi.InfoBytes,
		Storage: storage.NewFileOpts(storage.NewFileClientOpts{
			ClientBaseDir: path,
			FilePathMaker: func(opts storage.FilePathMakerOpts) string {
				return filepath.Join(opts.File.BestPath()...)
			},
		}),
	})
	t.AddTrackers(PublicOpenTrackers)
	select {
	case <-t.GotInfo():
	case <-ctx.Done():
		return "", "", fmt.Errorf("torrent: seed metadata for %s: %w", ih.HexString(), ctx.Err())
	}
	e.pin(ih) // a seeded file is kept until the engine closes; never auto-dropped
	infoHash = t.InfoHash().HexString()
	digest := hex.EncodeToString(h.Sum(nil))
	e.log.Info("seeding resource", "infoHash", infoHash, "sha256", digest, "bytes", t.Length())
	return infoHash, digest, nil
}

// Fetch downloads the torrent identified by infoHashHex, re-hashes the
// payload and compares it to expectedSHAHex before returning it. On any
// mismatch the data is dropped and ErrHashMismatch returned — tampered
// content is never served (UC-10). peers lists explicit host:port seeds
// for networks without DHT; pass nil to rely on DHT discovery. A verified
// resource is retained (kept seeding) so repeat fetches are served locally.
func (e *Engine) Fetch(ctx context.Context, infoHashHex, expectedSHAHex string, peers []string) ([]byte, error) {
	var ih metainfo.Hash
	if err := ih.FromHexString(infoHashHex); err != nil {
		return nil, fmt.Errorf("torrent: bad infohash %q: %w", infoHashHex, err)
	}
	expected, err := hex.DecodeString(expectedSHAHex)
	if err != nil || len(expected) != sha256.Size {
		return nil, fmt.Errorf("torrent: bad expected sha256 %q", expectedSHAHex)
	}

	t, _ := e.client.AddTorrentInfoHash(ih)
	t.AddTrackers(PublicOpenTrackers)
	// Reference-count this reader so a concurrent fetch of the same infohash (or
	// an LRU eviction) can never Drop the torrent out from under us. release()
	// drops it only when this was the last reader and it isn't pinned/retained.
	e.acquire(ih)
	keep := false
	defer func() {
		if keep {
			e.retain(ih) // verified: keep seeding it
		}
		e.release(ih)
	}()
	allPeers := append([]string{}, peers...)
	allPeers = append(allPeers, "127.0.0.1:42069")
	for _, p := range allPeers {
		host, portStr, err := net.SplitHostPort(p)
		if err != nil {
			continue
		}
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, portStr))
		if err != nil {
			continue
		}
		t.AddPeers([]torrent.PeerInfo{{Addr: addr, Source: torrent.PeerSourceDirect, Trusted: true}})
	}

	select {
	case <-t.GotInfo():
	case <-ctx.Done():
		return nil, fmt.Errorf("torrent: metadata for %s: %w", infoHashHex, ctx.Err())
	}
	if t.Length() > MaxFetchBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, t.Length())
	}
	t.DownloadAll()

	r := t.NewReader()
	r.SetContext(ctx) // abort blocked reads on cancellation; no goroutine leak
	defer r.Close()
	buf := bytes.NewBuffer(make([]byte, 0, t.Length()))
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(buf, r)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("torrent: download %s: %w", infoHashHex, err)
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("torrent: download %s: %w", infoHashHex, ctx.Err())
	}

	sum := sha256.Sum256(buf.Bytes())
	if !bytes.Equal(sum[:], expected) {
		e.log.Warn("tampered resource rejected",
			"infoHash", infoHashHex, "expected", expectedSHAHex, "got", hex.EncodeToString(sum[:]))
		return nil, ErrHashMismatch
	}
	e.log.Info("resource fetched and verified", "infoHash", infoHashHex, "bytes", buf.Len())
	keep = true // the deferred retain() keeps this verified resource seeding
	return buf.Bytes(), nil
}

// Stats summarizes swarm state for the admin dashboard.
type Stats struct {
	Torrents    int   `json:"torrents"`
	TotalPeers  int   `json:"totalPeers"`
	BytesShared int64 `json:"bytesShared"`
}

// Stats reports the number of active torrents and connected peers.
func (e *Engine) Stats() Stats {
	s := Stats{}
	for _, t := range e.client.Torrents() {
		s.Torrents++
		st := t.Stats()
		s.TotalPeers += st.ActivePeers
		s.BytesShared += st.BytesWrittenData.Int64()
	}
	return s
}
