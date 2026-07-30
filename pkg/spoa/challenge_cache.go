package spoa

import (
	"errors"
	"sync"

	"github.com/bluele/gcache"
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

// challengeCache is a small adapter around the cache implementation already
// used by CrowdSec. It keeps the challenge-specific single-use LoadAndDelete
// semantics while delegating size/TTL eviction to gcache.
type challengeCache struct {
	mu       sync.Mutex
	cache    gcache.Cache
	maxItems int
}

// newChallengeCache creates a challengeCache bounded to maxItems entries.
// maxItems <= 0 falls back to defaultChallengeCacheMaxEntries.
func newChallengeCache(maxItems int) *challengeCache {
	if maxItems <= 0 {
		maxItems = defaultChallengeCacheMaxEntries
	}

	return &challengeCache{
		cache:    gcache.New(maxItems).LRU().Expiration(challengeResponseTTL).Build(),
		maxItems: maxItems,
	}
}

// Store inserts or replaces the entry for key. If adding a genuinely new key
// would exceed maxItems, gcache evicts the least-recently-used entry.
func (c *challengeCache) Store(key string, value *challengeResponseEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	_ = c.cache.SetWithExpire(key, value, challengeResponseTTL)
}

// Load returns the entry for key, if present, without removing it.
func (c *challengeCache) Load(key string) (*challengeResponseEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	value, err := c.cache.GetIFPresent(key)
	if errors.Is(err, gcache.KeyNotFoundError) {
		return nil, false
	}
	if err != nil {
		return nil, false
	}

	entry, ok := value.(*challengeResponseEntry)
	return entry, ok
}

// LoadAndDelete returns the entry for key, if present, and removes it -
// giving the single-fetch-then-gone semantics the challenge HTTP backend
// relies on.
func (c *challengeCache) LoadAndDelete(key string) (*challengeResponseEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	value, err := c.cache.GetIFPresent(key)
	if errors.Is(err, gcache.KeyNotFoundError) {
		return nil, false
	}
	if err != nil {
		return nil, false
	}

	c.cache.Remove(key)

	entry, ok := value.(*challengeResponseEntry)
	return entry, ok
}

// Delete removes the entry for key, if present.
func (c *challengeCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Remove(key)
}

// Range calls f for every unexpired entry, stopping early if f returns false.
// The traversal is snapshotted under the lock before f is invoked, so f is free
// to call Delete without deadlocking.
func (c *challengeCache) Range(f func(key string, value *challengeResponseEntry) bool) {
	c.mu.Lock()
	items := c.cache.GetALL(true)
	snapshot := make(map[string]*challengeResponseEntry, len(items))
	for key, value := range items {
		keyString, ok := key.(string)
		if !ok {
			continue
		}
		entry, ok := value.(*challengeResponseEntry)
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
