package dataset

import (
	"strings"
	"sync"
)

// stringInternPool provides string interning to reduce memory usage.
// Origin strings are highly repetitive (e.g., "crowdsec", "cscli", "lists:scenario")
// and interning ensures we store only one copy of each unique string.
//
// This is critical because when we extract strings from Decision structs
// (e.g., *decision.Origin), Go shares the underlying byte array with the
// original struct. Without interning/cloning, the entire DecisionsStreamResponse
// stays in memory because we hold references to its string data.
var stringInternPool sync.Map

// internString returns an interned copy of the string.
// If the string was seen before, returns the existing interned version.
// If new, clones it (breaking any reference to source memory) and stores it.
//
// This provides two benefits:
// 1. Breaks references to Decision struct memory (allows GC)
// 2. Deduplicates repeated strings (memory efficiency)
func internString(s string) string {
	// Fast path: string already interned
	if existing, ok := stringInternPool.Load(s); ok {
		if str, ok := existing.(string); ok {
			return str
		}
	}

	// Slow path: clone and store
	// strings.Clone creates a fresh copy with its own backing array
	cloned := strings.Clone(s)

	// LoadOrStore handles the race where another goroutine might have
	// stored the same string between our Load and this call
	if existing, loaded := stringInternPool.LoadOrStore(cloned, cloned); loaded {
		if str, ok := existing.(string); ok {
			return str
		}
	}

	return cloned
}

// InternedPoolSize returns the number of unique strings in the intern pool.
// Useful for monitoring/debugging.
func InternedPoolSize() int {
	count := 0
	stringInternPool.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}
