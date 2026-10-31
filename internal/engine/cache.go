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

// put stores matches and returns their id; matches larger than the whole
// cache are cut to fit.
func (c *resultCache) put(ms []match) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	size := matchesSize(ms)
	for size > c.max && len(ms) > 0 {
		ms = ms[:len(ms)/2]
		size = matchesSize(ms)
	}
	for c.size+size > c.max && len(c.order) > 0 {
		old := c.order[0]
		c.order = c.order[1:]
		c.size -= c.entries[old].size
		delete(c.entries, old)
	}
	var b [12]byte
	rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	c.entries[id] = cacheEntry{ms: ms, size: size}
	c.order = append(c.order, id)
	c.size += size
	return id
}

// take removes and returns the matches of id.
func (c *resultCache) take(id string) ([]match, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok {
		return nil, false
	}
	delete(c.entries, id)
	for i, o := range c.order {
		if o == id {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.size -= e.size
	return e.ms, true
}
