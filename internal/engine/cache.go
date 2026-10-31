package engine

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// resultCache keeps the matches a page could not hold, for the next page
// (bounded in bytes, oldest evicted first). A policy change invalidates it
// with every cursor (their fingerprint no longer matches).
type resultCache struct {
	mu      sync.Mutex
	max     int
	size    int
	order   []string
	entries map[string]cacheEntry
}

type cacheEntry struct {
	ms   []match
	size int
}

func newResultCache(max int) *resultCache {
	return &resultCache{max: max, entries: map[string]cacheEntry{}}
}

func matchesSize(ms []match) int {
	n := 0
	for _, m := range ms {
		n += len(m.out) + 64
	}
	return n
}

// fits reports whether matches of size bytes can be cached at all.
func (c *resultCache) fits(size int) bool { return size <= c.max }

// put stores matches and returns their id. Matches are never cut (the
// cursor is past the granules they came from: a cut would lose them while
// the search reports complete); ok is false when they exceed the whole
// cache.
func (c *resultCache) put(ms []match) (id string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	size := matchesSize(ms)
	if size > c.max {
		return "", false
	}
	for c.size+size > c.max && len(c.order) > 0 {
		old := c.order[0]
		c.order = c.order[1:]
		c.size -= c.entries[old].size
		delete(c.entries, old)
	}
	var b [12]byte
	rand.Read(b[:])
	id = hex.EncodeToString(b[:])
	c.entries[id] = cacheEntry{ms: ms, size: size}
	c.order = append(c.order, id)
	c.size += size
	return id, true
}

// get returns the matches of id, leaving them in place: a continuation
// drops them only once it succeeded, so a failed one can be retried.
func (c *resultCache) get(id string) ([]match, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	return e.ms, ok
}

// drop removes the matches of id.
func (c *resultCache) drop(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok {
		return
	}
	delete(c.entries, id)
	for i, o := range c.order {
		if o == id {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.size -= e.size
}
