package dataset

import (
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestInternString(t *testing.T) {
	// Clear the pool before testing
	stringInternPool = sync.Map{}

	t.Run("returns same pointer for same string", func(t *testing.T) {
		s1 := internString("crowdsec")
		s2 := internString("crowdsec")

		// Both should point to the same underlying string
		assert.Equal(t, s1, s2)
		// Verify they share the same memory (pointer comparison)
		assert.Equal(t, unsafe.StringData(s1), unsafe.StringData(s2), "interned strings should share same backing array")
	})

	t.Run("clones string on first intern", func(t *testing.T) {
		// Clear the pool
		stringInternPool = sync.Map{}

		// When a string is first interned, strings.Clone is called
		// This test verifies that subsequent calls return the interned version
		first := internString("test_clone")
		second := internString("test_clone")

		// Both should be equal and share the same backing array
		assert.Equal(t, first, second)
		assert.Equal(t, unsafe.StringData(first), unsafe.StringData(second),
			"subsequent calls should return the same interned string")
	})

	t.Run("pool size tracks unique strings", func(t *testing.T) {
		// Clear the pool
		stringInternPool = sync.Map{}

		internString("alpha")
		internString("beta")
		internString("gamma")
		internString("alpha") // duplicate
		internString("beta")  // duplicate

		assert.Equal(t, 3, InternedPoolSize(), "pool should have 3 unique strings")
	})

	t.Run("empty string handling", func(t *testing.T) {
		result := internString("")
		assert.Empty(t, result)
	})
}

func BenchmarkInternString(b *testing.B) {
	// Pre-populate with some strings
	stringInternPool = sync.Map{}
	for range 100 {
		internString("crowdsec")
		internString("cscli")
		internString("lists:crowdsecurity/http-probing")
	}

	b.Run("existing_string", func(b *testing.B) {
		for range b.N {
			internString("crowdsec")
		}
	})

	b.Run("new_string", func(b *testing.B) {
		stringInternPool = sync.Map{}
		for i := range b.N {
			// Force new string each iteration to measure clone cost
			s := string([]byte{'t', 'e', 's', 't', byte(i % 256)})
			internString(s)
		}
	})
}

