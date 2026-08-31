package spoa

import (
	"errors"
	"math"
	"sync"
	"time"

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

// challengeRelayCacheRatio scales the configured cache size into the relay
// cache's own cap, so operators keep a single knob. Relay entries live this many
// times longer than response entries, so they need proportionally more slots to
// absorb the same rate of newly issued challenges before evicting. The extra
// slots are cheap: a challengeRelayEntry is a couple hundred bytes, against up
// to 1MiB for a challengeResponseEntry.
const challengeRelayCacheRatio = int(challengeRelayTTL / challengeResponseTTL)

// challengeCache is a small adapter around the cache implementation already
// used by CrowdSec. It keeps the challenge-specific single-use LoadAndDelete
// semantics while delegating size/TTL eviction to gcache.
//
// Both challenge-side stores use it. LRU is the right policy for each: under a
// flood the entries worth evicting are exactly the ones nobody ever fetches,
// while a browser actually working through a challenge keeps touching its own
// entries and so stays at the hot end of the list.
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

// newChallengeRelayCache creates the cache holding challenge relay entries,
// bounded to challengeRelayCacheRatio times the configured response cap so a
// flood of issued-but-never-solved challenges cannot grow memory without bound.
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
