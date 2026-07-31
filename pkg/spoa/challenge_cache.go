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
// Two things bound this cache, and they cover different failure modes. This cap
// is the hard ceiling: a burst of challenge-triggering requests that never
// complete their fetch (or a deliberate flood aimed at the AppSec challenge path)
// evicts least-recently-used entries rather than growing, with each entry costing
// up to maxAppSecResponseBodySize (1MiB). cleanupChallengeResponses' periodic
// sweep is the softer one: it releases entries whose TTL has passed, which
// nothing else does - gcache drops an expired entry when its key is next looked
// up, and an issued-but-never-fetched challenge is never looked up.
//
// 1000 entries is a generous ceiling for legitimate traffic - at the 30s
// challengeResponseTTL, that's ~33 newly issued challenges per second sustained
// before eviction kicks in - while still capping worst-case memory to a known
// amount instead of growing unbounded. Configurable via
// challenge_cache_max_entries in the bouncer config (see
// pkg/cfg.BouncerConfig.ChallengeCacheMaxEntries); a value <= 0 falls back to
// this default.
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

// Range calls f for every entry still held in memory - including ones gcache
// already considers expired - stopping early if f returns false. The traversal is
// snapshotted under the lock before f is invoked, so f is free to call Delete
// without deadlocking.
//
// Expired entries are included deliberately: gcache's LRU never reclaims on its
// own (an expired item stays in its map until that key is touched again or size
// pressure evicts it), and it exposes no purge-expired call - Purge() drops
// everything. Sweeping is therefore the only way to release the memory early, and
// a sweep that cannot see expired entries has nothing to release. Callers that
// want live entries only must use Load/LoadAndDelete, which do honor the TTL.
func (c *challengeCache) Range(f func(key string, value *challengeResponseEntry) bool) {
	c.mu.Lock()
	items := c.cache.GetALL(false)
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
