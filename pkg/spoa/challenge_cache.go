package spoa

import (
	"errors"
	"math"
	"sync"
	"time"

	"github.com/bluele/gcache"
)

// defaultChallengeCacheMaxEntries caps how many pending challenge responses are held
// in memory. Past the cap the least recently used entry is evicted.
const defaultChallengeCacheMaxEntries = 1000

// challengeRelayCacheRatio scales the configured cap for the relay cache, whose
// entries live longer and are far smaller than challenge responses.
const challengeRelayCacheRatio = int(challengeRelayTTL / challengeResponseTTL)

// challengeCache wraps gcache with single-use LoadAndDelete semantics. It uses LRU, so
// under a flood the entries evicted are the ones nobody ever fetches.
type challengeCache[T any] struct {
	mu       sync.Mutex
	cache    gcache.Cache
	maxItems int
	ttl      time.Duration
}

// newBoundedChallengeCache creates a challengeCache holding at most maxItems
// entries, each expiring after ttl. maxItems <= 0 falls back to
// defaultChallengeCacheMaxEntries.
func newBoundedChallengeCache[T any](maxItems int, ttl time.Duration) *challengeCache[T] {
	if maxItems <= 0 {
		maxItems = defaultChallengeCacheMaxEntries
	}

	return &challengeCache[T]{
		cache:    gcache.New(maxItems).LRU().Expiration(ttl).Build(),
		maxItems: maxItems,
		ttl:      ttl,
	}
}

// newChallengeCache creates the cache holding pending challenge responses.
// maxItems <= 0 falls back to defaultChallengeCacheMaxEntries.
func newChallengeCache(maxItems int) *challengeCache[*challengeResponseEntry] {
	return newBoundedChallengeCache[*challengeResponseEntry](maxItems, challengeResponseTTL)
}

// newChallengeRelayCache creates the relay cache, scaled by challengeRelayCacheRatio.
// maxItems <= 0 falls back to defaultChallengeCacheMaxEntries before scaling.
func newChallengeRelayCache(maxItems int) *challengeCache[challengeRelayEntry] {
	if maxItems <= 0 {
		maxItems = defaultChallengeCacheMaxEntries
	}
	if maxItems > math.MaxInt/challengeRelayCacheRatio {
		maxItems = math.MaxInt / challengeRelayCacheRatio
	}

	return newBoundedChallengeCache[challengeRelayEntry](maxItems*challengeRelayCacheRatio, challengeRelayTTL)
}

// Store inserts or replaces the entry for key. If adding a genuinely new key
// would exceed maxItems, gcache evicts the least-recently-used entry.
func (c *challengeCache[T]) Store(key string, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()

	_ = c.cache.SetWithExpire(key, value, c.ttl)
}

// Load returns the entry for key, if present, without removing it.
func (c *challengeCache[T]) Load(key string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.get(key)
}

// LoadAndDelete returns the entry for key, if present, and removes it -
// giving the single-fetch-then-gone semantics the challenge HTTP backend
// relies on.
func (c *challengeCache[T]) LoadAndDelete(key string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.get(key)
	if !ok {
		return entry, false
	}
	c.cache.Remove(key)

	return entry, true
}

// get performs the lookup shared by Load and LoadAndDelete. Callers must hold
// the lock.
func (c *challengeCache[T]) get(key string) (T, bool) {
	var zero T

	value, err := c.cache.GetIFPresent(key)
	if errors.Is(err, gcache.KeyNotFoundError) {
		return zero, false
	}
	if err != nil {
		return zero, false
	}

	entry, ok := value.(T)

	return entry, ok
}

// Delete removes the entry for key, if present.
func (c *challengeCache[T]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Remove(key)
}

// Range calls f for every entry still in memory, expired ones included, and stops early
// if f returns false. Sweeping is the only thing that frees expired entries.
func (c *challengeCache[T]) Range(f func(key string, value T) bool) {
	c.mu.Lock()
	items := c.cache.GetALL(false)
	snapshot := make(map[string]T, len(items))
	for key, value := range items {
		keyString, ok := key.(string)
		if !ok {
			continue
		}
		entry, ok := value.(T)
		if !ok {
			continue
		}
		snapshot[keyString] = entry
	}
	c.mu.Unlock()

	for key, entry := range snapshot {
		if !f(key, entry) {
			return
		}
	}
}
