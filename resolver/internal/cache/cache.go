// Package cache implements the resolver's TTL cache layer (HLD §3.3): a
// bounded LRU keyed by (domain, record_type, selector) whose entries honour
// the per-record TTL stored on-chain, plus proactive invalidation driven by
// contract events (HLD open issue 5: TTL + push).
package cache

import (
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
)

// Key identifies a cached answer.
type Key struct {
	Name     string
	Type     string
	Selector string
}

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

// Stats is a snapshot of cache counters (consumed by the admin dashboard).
type Stats struct {
	Hits      uint64 `json:"hits"`
	Misses    uint64 `json:"misses"`
	Evictions uint64 `json:"evictions"`
	Entries   int    `json:"entries"`
	Capacity  int    `json:"capacity"`
}

// TTLCache is a thread-safe bounded LRU with per-entry TTL expiry and
// name-level invalidation.
//
// A single mutex (mu) guards BOTH the LRU and the two name indexes. Every LRU
// mutation runs under mu, and the eviction callback (dropFromIndex) therefore
// assumes mu is already held by the calling goroutine and never re-locks. This
// makes Set atomic (index + LRU insert in one critical section) so a
// concurrent invalidation can never slip into a window where the key is in the
// index but not yet in the LRU — the race that previously let a stale entry
// survive push-invalidation.
type TTLCache[V any] struct {
	lru      *lru.Cache[Key, entry[V]]
	capacity int
	now      func() time.Time // injectable clock for tests

	mu        sync.Mutex                  // guards lru AND the two indexes below
	nameKeys  map[string]map[Key]struct{} // name -> live keys
	hashNames map[[32]byte]string         // keccak256(name) -> name

	hits, misses, evictions atomic.Uint64
}

// New creates a cache holding at most capacity entries.
func New[V any](capacity int) (*TTLCache[V], error) {
	c := &TTLCache[V]{
		capacity:  capacity,
		now:       time.Now,
		nameKeys:  map[string]map[Key]struct{}{},
		hashNames: map[[32]byte]string{},
	}
	inner, err := lru.NewWithEvict[Key, entry[V]](capacity, func(k Key, _ entry[V]) {
		c.evictions.Add(1)
		c.dropFromIndex(k)
	})
	if err != nil {
		return nil, err
	}
	c.lru = inner
	return c, nil
}

// Get returns the cached value if present and not expired.
func (c *TTLCache[V]) Get(k Key) (V, bool) {
	var zero V
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.lru.Get(k)
	if !ok {
		c.misses.Add(1)
		return zero, false
	}
	if c.now().After(e.expiresAt) {
		c.lru.Remove(k) // evict callback cleans the index (mu held)
		c.misses.Add(1)
		return zero, false
	}
	c.hits.Add(1)
	return e.value, true
}

// Set stores value under k for ttl. The index registration and the LRU insert
// happen in one critical section so invalidation cannot race the insert.
func (c *TTLCache[V]) Set(k Key, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys, ok := c.nameKeys[k.Name]
	if !ok {
		keys = map[Key]struct{}{}
		c.nameKeys[k.Name] = keys
		c.hashNames[nameHash(k.Name)] = k.Name
	}
	keys[k] = struct{}{}
	c.lru.Add(k, entry[V]{value: value, expiresAt: c.now().Add(ttl)})
}

// InvalidateName drops every entry (all types/selectors) of a domain.
func (c *TTLCache[V]) InvalidateName(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidateNameLocked(name)
}

// invalidateNameLocked removes all of a domain's entries; caller holds mu.
func (c *TTLCache[V]) invalidateNameLocked(name string) {
	keys := make([]Key, 0, len(c.nameKeys[name]))
	for k := range c.nameKeys[name] {
		keys = append(keys, k)
	}
	for _, k := range keys {
		c.lru.Remove(k) // evict callback drops k from the index (mu held)
	}
}

// InvalidateNameHash drops entries of the domain whose keccak256(name)
// equals hash. Used for Transferred events, which carry only the hash; only
// names we have cached can (and need to) be matched.
func (c *TTLCache[V]) InvalidateNameHash(hash [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if name, ok := c.hashNames[hash]; ok {
		c.invalidateNameLocked(name)
	}
}

// HandleEvent applies a contract event to the cache (push invalidation).
func (c *TTLCache[V]) HandleEvent(ev chain.RecordEvent) {
	switch ev.Kind {
	case chain.EventTransferred:
		c.InvalidateNameHash(ev.NameHash)
	default: // registered, record_set, record_removed all carry the name
		c.InvalidateName(ev.Name)
	}
}

// Stats returns a counter snapshot.
func (c *TTLCache[V]) Stats() Stats {
	return Stats{
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Evictions: c.evictions.Load(),
		Entries:   c.lru.Len(),
		Capacity:  c.capacity,
	}
}

// dropFromIndex removes k from the name indexes. It is the LRU eviction
// callback and is only ever invoked from an LRU mutation that already holds
// mu, so it must NOT re-lock (sync.Mutex is not reentrant).
func (c *TTLCache[V]) dropFromIndex(k Key) {
	if keys, ok := c.nameKeys[k.Name]; ok {
		delete(keys, k)
		if len(keys) == 0 {
			delete(c.nameKeys, k.Name)
			delete(c.hashNames, nameHash(k.Name))
		}
	}
}
