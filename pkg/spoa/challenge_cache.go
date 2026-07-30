package spoa

import (
	"container/list"
	"sync"
)

// defaultChallengeCacheMaxEntries bounds how many pending AppSec challenge
// responses (see challengeResponseEntry) can be held in memory at once,
// waiting for HAProxy to fetch them via the challenge HTTP backend.
//
// Without a cap, a burst of challenge-triggering requests that never complete
// their fetch (or a deliberate flood aimed at the AppSec challenge path)
// could grow this cache without bound between cleanupChallengeResponses'
// periodic TTL sweeps, with each entry costing up to
// maxAppSecResponseBodySize (1MiB). 1000 entries is a generous ceiling for
// legitimate traffic - at the 30s challengeResponseTTL, that's ~33 newly
// issued challenges per second sustained before eviction kicks in - while
// still capping worst-case memory to a known amount instead of growing
// unbounded. Configurable via challenge_cache_max_entries in the bouncer
// config (see pkg/cfg.BouncerConfig.ChallengeCacheMaxEntries); a value <= 0
// falls back to this default.
const defaultChallengeCacheMaxEntries = 1000

// challengeCache is a bounded, concurrency-safe cache of pending challenge
// responses keyed by a token. Once at capacity, storing a new entry evicts
// the oldest one first (by insertion order, not last-access) rather than
// rejecting the new entry or growing past the configured limit - a request
// that's been waiting longest to be fetched is the best candidate to drop.
type challengeCache struct {
	mu       sync.Mutex
	ll       *list.List // front = oldest, back = most recently inserted/updated
	items    map[string]*list.Element
	maxItems int
}

// challengeCacheEntry is the value stored in the backing list; ll.Element.Value
// is always a *challengeCacheEntry.
type challengeCacheEntry struct {
	key   string
	value *challengeResponseEntry
}

// newChallengeCache creates a challengeCache bounded to maxItems entries.
// maxItems <= 0 falls back to defaultChallengeCacheMaxEntries.
func newChallengeCache(maxItems int) *challengeCache {
	if maxItems <= 0 {
		maxItems = defaultChallengeCacheMaxEntries
	}

	return &challengeCache{
		ll:       list.New(),
		items:    make(map[string]*list.Element),
		maxItems: maxItems,
	}
}

// Store inserts or replaces the entry for key. A replaced key is moved to the
// back (treated as freshly inserted). If adding a genuinely new key would
// exceed maxItems, the oldest entry is evicted first to make room - Store
// never fails or drops the entry being stored.
func (c *challengeCache) Store(key string, value *challengeResponseEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		el.Value.(*challengeCacheEntry).value = value //nolint:forcetypeassert // only *challengeCacheEntry is ever stored in c.ll
		c.ll.MoveToBack(el)
		return
	}

	for c.ll.Len() >= c.maxItems {
		oldest := c.ll.Front()
		if oldest == nil {
			break
		}
		c.removeElementLocked(oldest)
	}

	el := c.ll.PushBack(&challengeCacheEntry{key: key, value: value})
	c.items[key] = el
}

// Load returns the entry for key, if present, without removing it.
func (c *challengeCache) Load(key string) (*challengeResponseEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return nil, false
	}

	return el.Value.(*challengeCacheEntry).value, true //nolint:forcetypeassert // only *challengeCacheEntry is ever stored in c.ll
}

// LoadAndDelete returns the entry for key, if present, and removes it -
// giving the single-fetch-then-gone semantics the challenge HTTP backend
// relies on.
func (c *challengeCache) LoadAndDelete(key string) (*challengeResponseEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return nil, false
	}

	value := el.Value.(*challengeCacheEntry).value //nolint:forcetypeassert // only *challengeCacheEntry is ever stored in c.ll
	c.removeElementLocked(el)

	return value, true
}

// Delete removes the entry for key, if present.
func (c *challengeCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		c.removeElementLocked(el)
	}
}

// Range calls f for every entry, oldest-inserted first, stopping early if f
// returns false. The traversal is snapshotted under the lock before f is
// invoked, so f is free to call Delete (including deleting the very entry it
// was just given, as cleanupChallengeResponses does) without deadlocking or
// corrupting iteration - matching sync.Map.Range's contract of tolerating
// concurrent deletion during a range.
func (c *challengeCache) Range(f func(key string, value *challengeResponseEntry) bool) {
	c.mu.Lock()
	snapshot := make([]challengeCacheEntry, 0, c.ll.Len())
	for el := c.ll.Front(); el != nil; el = el.Next() {
		ce := el.Value.(*challengeCacheEntry) //nolint:revive,forcetypeassert // only *challengeCacheEntry is ever stored in c.ll
		snapshot = append(snapshot, challengeCacheEntry{key: ce.key, value: ce.value})
	}
	c.mu.Unlock()

	for _, entry := range snapshot {
		if !f(entry.key, entry.value) {
			return
		}
	}
}

// removeElementLocked removes el from both the list and the key index.
// Caller must hold c.mu.
func (c *challengeCache) removeElementLocked(el *list.Element) {
	entry := el.Value.(*challengeCacheEntry) //nolint:revive,forcetypeassert // only *challengeCacheEntry is ever stored in c.ll
	delete(c.items, entry.key)
	c.ll.Remove(el)
}
