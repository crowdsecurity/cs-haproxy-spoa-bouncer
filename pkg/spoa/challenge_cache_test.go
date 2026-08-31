package spoa

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Range must surface entries that gcache's own TTL has already retired, because
// sweeping them is the only thing that releases their memory. gcache drops an
// expired item when that key is next looked up, but a challenge that HAProxy never
// fetches is never looked up - which is exactly the entry that leaks - so nothing
// reclaims it until size pressure evicts it. Expiry is driven through gcache here
// rather than by hand-setting expiresAt, so the test uses the same clock as
// production. Note the ordering: Range runs before Load, because Load on an
// expired key removes it and would mask the very thing being asserted.
func TestChallengeCache_RangeSeesEntriesGcacheHasExpired(t *testing.T) {
	c := newChallengeCache(10)

	require.NoError(t, c.cache.SetWithExpire("stale", &challengeResponseEntry{body: "old"}, time.Nanosecond))
	time.Sleep(time.Millisecond)

	seen := map[string]bool{}
	c.Range(func(key string, _ *challengeResponseEntry) bool {
		seen[key] = true
		return true
	})
	assert.True(t, seen["stale"], "Range must see the expired entry, otherwise the sweep can never reclaim it")

	_, ok := c.Load("stale")
	assert.False(t, ok, "an expired entry must never be servable")

	c.Delete("stale")

	seen = map[string]bool{}
	c.Range(func(key string, _ *challengeResponseEntry) bool {
		seen[key] = true
		return true
	})
	assert.Empty(t, seen, "the entry should be gone once swept")
}

func TestNewChallengeCache_DefaultsWhenNonPositive(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		c := newChallengeCache(n)
		assert.Equal(t, defaultChallengeCacheMaxEntries, c.maxItems, "maxItems=%d should fall back to the default", n)
	}
}

func TestChallengeCache_StoreLoadDelete(t *testing.T) {
	c := newChallengeCache(10)

	_, ok := c.Load("missing")
	assert.False(t, ok)

	entry := &challengeResponseEntry{body: "hello"}
	c.Store("k", entry)

	got, ok := c.Load("k")
	require.True(t, ok)
	assert.Same(t, entry, got)

	c.Delete("k")
	_, ok = c.Load("k")
	assert.False(t, ok, "deleted entry should no longer be present")
}

func TestChallengeCache_LoadAndDeleteIsSingleUse(t *testing.T) {
	c := newChallengeCache(10)
	c.Store("k", &challengeResponseEntry{body: "once"})

	got, ok := c.LoadAndDelete("k")
	require.True(t, ok)
	assert.Equal(t, "once", got.body)

	_, ok = c.LoadAndDelete("k")
	assert.False(t, ok, "a second fetch of the same token must miss")
}

func TestChallengeCache_StoreOnExistingKeyDoesNotEvict(t *testing.T) {
	c := newChallengeCache(2)
	c.Store("a", &challengeResponseEntry{body: "a1"})
	c.Store("b", &challengeResponseEntry{body: "b1"})

	// Re-storing an existing key at capacity must update in place, not evict
	// another entry to make room - it isn't a net-new entry.
	c.Store("a", &challengeResponseEntry{body: "a2"})

	got, ok := c.Load("a")
	require.True(t, ok)
	assert.Equal(t, "a2", got.body)

	_, ok = c.Load("b")
	assert.True(t, ok, "unrelated entry must survive an update to a different key")
}

func TestChallengeCache_EvictsLeastRecentlyUsedUnderPressure(t *testing.T) {
	c := newChallengeCache(3)

	c.Store("first", &challengeResponseEntry{body: "1"})
	c.Store("second", &challengeResponseEntry{body: "2"})
	c.Store("third", &challengeResponseEntry{body: "3"})

	_, ok := c.Load("first")
	require.True(t, ok)

	// At capacity: inserting a 4th distinct key must evict the least-recently
	// used entry. "first" was just read, so "second" is evicted.
	c.Store("fourth", &challengeResponseEntry{body: "4"})

	_, ok = c.Load("second")
	assert.False(t, ok, "least-recently used entry should have been evicted to make room")

	for _, key := range []string{"first", "third", "fourth"} {
		_, ok := c.Load(key)
		assert.True(t, ok, "entry %q should still be present", key)
	}

	// Cache never grows past its configured bound.
	count := 0
	c.Range(func(string, *challengeResponseEntry) bool {
		count++
		return true
	})
	assert.Equal(t, 3, count)
}

func TestChallengeCache_EvictionContinuesUnderSustainedPressure(t *testing.T) {
	c := newChallengeCache(5)

	for i := range 100 {
		c.Store(string(rune('a'+i%26))+string(rune(i)), &challengeResponseEntry{})
	}

	count := 0
	c.Range(func(string, *challengeResponseEntry) bool {
		count++
		return true
	})
	assert.Equal(t, 5, count, "cache must stay bounded no matter how many entries are stored over time")
}

func TestChallengeCache_RangeToleratesDeleteDuringRange(t *testing.T) {
	c := newChallengeCache(10)
	c.Store("a", &challengeResponseEntry{body: "1"})
	c.Store("b", &challengeResponseEntry{body: "2"})
	c.Store("c", &challengeResponseEntry{body: "3"})

	visited := map[string]bool{}
	c.Range(func(key string, _ *challengeResponseEntry) bool {
		visited[key] = true
		// Mirrors cleanupChallengeResponses: delete the entry currently being
		// visited from inside the callback.
		c.Delete(key)
		return true
	})

	assert.Equal(t, map[string]bool{"a": true, "b": true, "c": true}, visited)

	count := 0
	c.Range(func(string, *challengeResponseEntry) bool {
		count++
		return true
	})
	assert.Equal(t, 0, count, "all entries deleted during Range should be gone afterward")
}

func TestChallengeCache_RangeStopsWhenCallbackReturnsFalse(t *testing.T) {
	c := newChallengeCache(10)
	c.Store("a", &challengeResponseEntry{})
	c.Store("b", &challengeResponseEntry{})
	c.Store("c", &challengeResponseEntry{})

	visited := 0
	c.Range(func(key string, _ *challengeResponseEntry) bool {
		visited++
		return false
	})

	assert.Equal(t, 1, visited, "Range must stop as soon as f returns false")
}

func TestNewChallengeRelayCache_ScalesTheConfiguredCap(t *testing.T) {
	// Relay entries live challengeRelayCacheRatio times longer than response
	// entries, so they get proportionally more slots from the same operator knob
	// - otherwise the relay cache would start evicting live challenges at a
	// fraction of the rate the response cache tolerates.
	assert.Equal(t, 10*challengeRelayCacheRatio, newChallengeRelayCache(10).maxItems)
	assert.Equal(t, defaultChallengeCacheMaxEntries*challengeRelayCacheRatio, newChallengeRelayCache(0).maxItems)
	assert.Positive(t, newChallengeRelayCache(math.MaxInt).maxItems, "scaling a huge cap must not overflow into a negative size")
}

func TestChallengeRelayCache_IsBounded(t *testing.T) {
	c := newBoundedChallengeCache[challengeRelayEntry](2, challengeRelayTTL)

	c.Store("first", challengeRelayEntry{host: "1"})
	c.Store("second", challengeRelayEntry{host: "2"})

	_, ok := c.Load("first")
	require.True(t, ok)

	// The point of the cap: a flood of issued-but-never-solved challenges evicts
	// the entries nobody came back for, rather than growing without bound. A
	// browser working through its challenge keeps touching its own entry, so
	// "first" survives and the untouched "second" goes.
	c.Store("third", challengeRelayEntry{host: "3"})

	_, ok = c.Load("second")
	assert.False(t, ok, "least-recently used relay should have been evicted to make room")

	got, ok := c.Load("first")
	require.True(t, ok, "a relay that is actively being used must not be evicted")
	assert.Equal(t, "1", got.host)
}
