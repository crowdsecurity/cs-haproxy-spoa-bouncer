package host

import (
	"testing"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/ban"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestMatchFirstHost_SingleHost(t *testing.T) {
	logger := log.NewEntry(log.New())
	manager := NewManager(logger)

	// Add a single host
	host := &Host{
		Host: "www.example.com",
		Ban:  ban.Ban{},
	}
	manager.addHost(host)

	// Test exact match
	matched := manager.MatchFirstHost("www.example.com")
	assert.NotNil(t, matched, "should match exact host")
	assert.Equal(t, "www.example.com", matched.Host, "matched host should be correct")

	// Test no match
	matched = manager.MatchFirstHost("other.example.com")
	assert.Nil(t, matched, "should not match different host")
}

func TestMatchFirstHost_Priority(t *testing.T) {
	// Table-driven test for priority matching
	// Tests that more specific patterns always win regardless of insertion order
	tests := []struct {
		name           string
		hostPatterns   []string // Patterns to add (in this order)
		lookupDomain   string
		expectedMatch  string
		expectedReason string
	}{
		{
			name:           "exact match wins over wildcard (specific first)",
			hostPatterns:   []string{"www.example.com", "*.example.com", "*"},
			lookupDomain:   "www.example.com",
			expectedMatch:  "www.example.com",
			expectedReason: "exact match should win over wildcard",
		},
		{
			name:           "exact match wins over wildcard (wildcard first)",
			hostPatterns:   []string{"*", "*.example.com", "www.example.com"},
			lookupDomain:   "www.example.com",
			expectedMatch:  "www.example.com",
			expectedReason: "most specific pattern should win regardless of order",
		},
		{
			name:           "wildcard matches subdomain (specific first)",
			hostPatterns:   []string{"www.example.com", "*.example.com", "*"},
			lookupDomain:   "api.example.com",
			expectedMatch:  "*.example.com",
			expectedReason: "wildcard pattern should match subdomain",
		},
		{
			name:           "wildcard matches subdomain (wildcard first)",
			hostPatterns:   []string{"*", "*.example.com", "www.example.com"},
			lookupDomain:   "api.example.com",
			expectedMatch:  "*.example.com",
			expectedReason: "*.example.com should win over *",
		},
		{
			name:           "catch-all matches unmatched (specific first)",
			hostPatterns:   []string{"www.example.com", "*.example.com", "*"},
			lookupDomain:   "other.com",
			expectedMatch:  "*",
			expectedReason: "catch-all should match any domain",
		},
		{
			name:           "catch-all matches unmatched (wildcard first)",
			hostPatterns:   []string{"*", "*.example.com", "www.example.com"},
			lookupDomain:   "other.com",
			expectedMatch:  "*",
			expectedReason: "catch-all should match when no other pattern matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := log.NewEntry(log.New())
			manager := NewManager(logger)

			// Add hosts in specified order
			for _, pattern := range tt.hostPatterns {
				manager.addHost(&Host{Host: pattern, Ban: ban.Ban{}})
			}

			matched := manager.MatchFirstHost(tt.lookupDomain)
			assert.NotNil(t, matched, "should match %s", tt.lookupDomain)
			assert.Equal(t, tt.expectedMatch, matched.Host, tt.expectedReason)
		})
	}
}

func TestMatchFirstHost_WildcardPatterns(t *testing.T) {
	logger := log.NewEntry(log.New())
	manager := NewManager(logger)

	// Test prefix wildcard
	host1 := &Host{
		Host: "*.example.com",
		Ban:  ban.Ban{},
	}
	manager.addHost(host1)

	matched := manager.MatchFirstHost("www.example.com")
	assert.NotNil(t, matched, "*.example.com should match www.example.com")
	assert.Equal(t, "*.example.com", matched.Host)

	matched = manager.MatchFirstHost("api.example.com")
	assert.NotNil(t, matched, "*.example.com should match api.example.com")
	assert.Equal(t, "*.example.com", matched.Host)

	matched = manager.MatchFirstHost("example.com")
	assert.Nil(t, matched, "*.example.com should not match example.com (no subdomain)")

	// Test suffix wildcard
	host2 := &Host{
		Host: "example.*",
		Ban:  ban.Ban{},
	}
	manager.addHost(host2)

	matched = manager.MatchFirstHost("example.com")
	assert.NotNil(t, matched, "example.* should match example.com")
	assert.Equal(t, "example.*", matched.Host)

	matched = manager.MatchFirstHost("example.org")
	assert.NotNil(t, matched, "example.* should match example.org")
	assert.Equal(t, "example.*", matched.Host)
}

func TestMatchFirstHost_ComplexWildcardPatterns(t *testing.T) {
	logger := log.NewEntry(log.New())
	manager := NewManager(logger)

	// Complex pattern with wildcard in middle (should use filepath.Match fallback)
	host1 := &Host{
		Host: "example.*.com",
		Ban:  ban.Ban{},
	}
	manager.addHost(host1)

	matched := manager.MatchFirstHost("example.test.com")
	assert.NotNil(t, matched, "example.*.com should match example.test.com")
	assert.Equal(t, "example.*.com", matched.Host)

	matched = manager.MatchFirstHost("example.api.com")
	assert.NotNil(t, matched, "example.*.com should match example.api.com")
	assert.Equal(t, "example.*.com", matched.Host)
}

func TestMatchFirstHost_Priority_LengthMatters(t *testing.T) {
	logger := log.NewEntry(log.New())
	manager := NewManager(logger)

	// Longer patterns should have higher priority
	host1 := &Host{
		Host: "*.com",
		Ban:  ban.Ban{},
	}
	host2 := &Host{
		Host: "*.example.com",
		Ban:  ban.Ban{},
	}

	manager.addHost(host1)
	manager.addHost(host2)

	// api.example.com should match the longer, more specific pattern
	matched := manager.MatchFirstHost("api.example.com")
	assert.NotNil(t, matched, "should match api.example.com")
	assert.Equal(t, "*.example.com", matched.Host, "longer pattern should win")
}

func TestMatchFirstHost_Cache(t *testing.T) {
	logger := log.NewEntry(log.New())
	manager := NewManager(logger)

	host1 := &Host{
		Host: "www.example.com",
		Ban:  ban.Ban{},
	}
	manager.addHost(host1)

	// First match should populate cache
	matched1 := manager.MatchFirstHost("www.example.com")
	assert.NotNil(t, matched1)

	// Second match should use cache
	matched2 := manager.MatchFirstHost("www.example.com")
	assert.NotNil(t, matched2)
	assert.Equal(t, matched1, matched2, "cached result should be returned")
}

func TestMatchFirstHost_NoHosts(t *testing.T) {
	logger := log.NewEntry(log.New())
	manager := NewManager(logger)

	matched := manager.MatchFirstHost("www.example.com")
	assert.Nil(t, matched, "should return nil when no hosts configured")
}

func TestMatchFirstHost_RemoveHost(t *testing.T) {
	logger := log.NewEntry(log.New())
	manager := NewManager(logger)

	host1 := &Host{
		Host: "www.example.com",
		Ban:  ban.Ban{},
	}
	host2 := &Host{
		Host: "*.example.com",
		Ban:  ban.Ban{},
	}

	manager.addHost(host1)
	manager.addHost(host2)

	// Should match
	matched := manager.MatchFirstHost("www.example.com")
	assert.NotNil(t, matched)
	assert.Equal(t, "www.example.com", matched.Host)

	// Remove host1
	manager.removeHost(host1)

	// Should now match wildcard
	matched = manager.MatchFirstHost("www.example.com")
	assert.NotNil(t, matched)
	assert.Equal(t, "*.example.com", matched.Host, "should match wildcard after exact match removed")
}

func TestMatchFirstHost_MultipleSpecificHosts(t *testing.T) {
	logger := log.NewEntry(log.New())
	manager := NewManager(logger)

	// Add multiple specific hosts
	host1 := &Host{
		Host: "www.example.com",
		Ban:  ban.Ban{},
	}
	host2 := &Host{
		Host: "api.example.com",
		Ban:  ban.Ban{},
	}
	host3 := &Host{
		Host: "*.example.com",
		Ban:  ban.Ban{},
	}

	manager.addHost(host1)
	manager.addHost(host2)
	manager.addHost(host3)

	// Each specific host should match itself
	matched := manager.MatchFirstHost("www.example.com")
	assert.NotNil(t, matched)
	assert.Equal(t, "www.example.com", matched.Host)

	matched = manager.MatchFirstHost("api.example.com")
	assert.NotNil(t, matched)
	assert.Equal(t, "api.example.com", matched.Host)

	// Other subdomains should match wildcard
	matched = manager.MatchFirstHost("test.example.com")
	assert.NotNil(t, matched)
	assert.Equal(t, "*.example.com", matched.Host)
}

func TestMatchFirstHost_CatchAllLastResort(t *testing.T) {
	logger := log.NewEntry(log.New())
	manager := NewManager(logger)

	// Add catch-all and specific pattern
	host1 := &Host{
		Host: "*",
		Ban:  ban.Ban{},
	}
	host2 := &Host{
		Host: "specific.com",
		Ban:  ban.Ban{},
	}

	manager.addHost(host1)
	manager.addHost(host2)

	// Specific should win
	matched := manager.MatchFirstHost("specific.com")
	assert.NotNil(t, matched)
	assert.Equal(t, "specific.com", matched.Host, "specific pattern should win over catch-all")

	// Catch-all should match anything else
	matched = manager.MatchFirstHost("other.com")
	assert.NotNil(t, matched)
	assert.Equal(t, "*", matched.Host, "catch-all should match when no specific pattern matches")
}
