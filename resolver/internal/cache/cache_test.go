package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
)

func newTestCache(t *testing.T, capacity int) (*TTLCache[string], *time.Time) {
	t.Helper()
	c, err := New[string](capacity)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	return c, &now
}

func TestGetSetAndTTLExpiry(t *testing.T) {
	c, now := newTestCache(t, 8)
	k := Key{Name: "example", Type: "A"}
	c.Set(k, "1.2.3.4", 60*time.Second)

	if v, ok := c.Get(k); !ok || v != "1.2.3.4" {
		t.Fatalf("Get = %q, %v", v, ok)
	}

	*now = now.Add(61 * time.Second)
	if _, ok := c.Get(k); ok {
		t.Fatal("expected expiry after TTL")
	}
	if s := c.Stats(); s.Hits != 1 || s.Misses != 1 || s.Entries != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestLRUEvictionMaintainsIndex(t *testing.T) {
	c, _ := newTestCache(t, 2)
	for i := 0; i < 3; i++ {
		c.Set(Key{Name: fmt.Sprintf("d%d", i), Type: "A"}, "v", time.Minute)
	}
	// d0 evicted by capacity
	if _, ok := c.Get(Key{Name: "d0", Type: "A"}); ok {
		t.Fatal("expected d0 evicted")
	}
	if s := c.Stats(); s.Evictions != 1 || s.Entries != 2 {
		t.Errorf("stats = %+v", s)
	}
	// index for d0 must be gone: hash invalidation of d0 is a no-op
	c.InvalidateNameHash(nameHash("d0"))
	if s := c.Stats(); s.Entries != 2 {
		t.Errorf("entries after no-op invalidation = %d", s.Entries)
	}
}

func TestInvalidateNameDropsAllSelectors(t *testing.T) {
	c, _ := newTestCache(t, 8)
	c.Set(Key{Name: "example", Type: "A"}, "v1", time.Minute)
	c.Set(Key{Name: "example", Type: "SVC", Selector: "service=HTTP"}, "v2", time.Minute)
	c.Set(Key{Name: "other", Type: "A"}, "v3", time.Minute)

	c.InvalidateName("example")

	if _, ok := c.Get(Key{Name: "example", Type: "A"}); ok {
		t.Error("example/A should be invalidated")
	}
	if _, ok := c.Get(Key{Name: "example", Type: "SVC", Selector: "service=HTTP"}); ok {
		t.Error("example/SVC should be invalidated")
	}
	if _, ok := c.Get(Key{Name: "other", Type: "A"}); !ok {
		t.Error("other domain must survive")
	}
}

func TestHandleEvent(t *testing.T) {
	c, _ := newTestCache(t, 8)
	k := Key{Name: "example", Type: "A"}

	cases := []chain.RecordEvent{
		{Kind: chain.EventRecordSet, Name: "example"},
		{Kind: chain.EventRecordRemoved, Name: "example"},
		{Kind: chain.EventRegistered, Name: "example"},
		{Kind: chain.EventTransferred, NameHash: nameHash("example")},
	}
	for _, ev := range cases {
		c.Set(k, "v", time.Minute)
		c.HandleEvent(ev)
		if _, ok := c.Get(k); ok {
			t.Errorf("event %s did not invalidate", ev.Kind)
		}
	}
}

// TestConcurrentSetInvalidateNoStaleSurvivors hammers Set/Get/InvalidateName/
// HandleEvent from many goroutines (run with -race). It then quiesces and
// asserts the central invariant of the single-mutex design: after every name
// is invalidated, no LRU entry is orphaned from the index — i.e. invalidation
// can always find and drop a cached entry. Before the fix, a Set racing an
// invalidation could leave a live, unreachable entry behind.
func TestConcurrentSetInvalidateNoStaleSurvivors(t *testing.T) {
	c, err := New[string](256)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 8
	const iters = 3000
	names := []string{"alpha", "bravo", "charlie", "delta"}
	sel := func(i int) string { return fmt.Sprintf("s%d", i%4) }

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				n := names[(seed+i)%len(names)]
				k := Key{Name: n, Type: "A", Selector: sel(i)}
				c.Set(k, "v", time.Minute)
				c.Get(k)
			}
		}(w)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				n := names[(seed+i)%len(names)]
				if i%2 == 0 {
					c.InvalidateName(n)
				} else {
					c.HandleEvent(chain.RecordEvent{Kind: chain.EventTransferred, NameHash: nameHash(n)})
				}
			}
		}(w)
	}
	wg.Wait()

	for _, n := range names {
		c.InvalidateName(n)
	}
	for _, n := range names {
		for i := 0; i < 4; i++ {
			if _, ok := c.Get(Key{Name: n, Type: "A", Selector: sel(i)}); ok {
				t.Fatalf("entry for %s/%s survived final invalidation (orphaned from index)", n, sel(i))
			}
		}
	}
	c.mu.Lock()
	leftNames, leftHashes := len(c.nameKeys), len(c.hashNames)
	c.mu.Unlock()
	if leftNames != 0 || leftHashes != 0 {
		t.Fatalf("index not empty after full invalidation: nameKeys=%d hashNames=%d", leftNames, leftHashes)
	}
	if n := c.lru.Len(); n != 0 {
		t.Fatalf("lru not empty after full invalidation: %d entries", n)
	}
}

func TestSetOverwriteRefreshesTTL(t *testing.T) {
	c, now := newTestCache(t, 8)
	k := Key{Name: "example", Type: "A"}
	c.Set(k, "old", 30*time.Second)
	*now = now.Add(20 * time.Second)
	c.Set(k, "new", 30*time.Second)
	*now = now.Add(20 * time.Second) // 40s after first set, 20s after second
	if v, ok := c.Get(k); !ok || v != "new" {
		t.Fatalf("Get = %q, %v; want refreshed entry", v, ok)
	}
}
