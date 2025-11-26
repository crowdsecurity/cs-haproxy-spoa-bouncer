package host

import (
	"math"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// minPriority is used to initialize priority comparisons.
	// Any valid pattern will have a higher priority than this.
	minPriority = math.MinInt
)

// domainTrieNode represents a node in the reverse domain trie.
// The trie is built by reversing domain names so "www.example.com" becomes ["com", "example", "www"].
// This allows efficient prefix matching for wildcard patterns like "*.example.com".
type domainTrieNode struct {
	// children maps exact domain segments to child nodes
	children map[string]*domainTrieNode
	// wildcardChild handles wildcard segment matches (e.g., "*" in "*.example.com")
	wildcardChild *domainTrieNode
	// host stores the Host configuration if this node represents a complete pattern
	host *Host
	// pattern stores the original pattern string for this node (used for priority calculation)
	pattern string
}

// domainTrie is a reverse domain trie for efficient host pattern matching.
// It provides O(m) lookup complexity where m is the number of domain segments,
// independent of the total number of hosts stored.
type domainTrie struct {
	root *domainTrieNode
	mu   sync.RWMutex
}

// newDomainTrie creates a new empty domain trie.
func newDomainTrie() *domainTrie {
	return &domainTrie{
		root: &domainTrieNode{
			children: make(map[string]*domainTrieNode),
		},
	}
}

// reverseDomain splits and reverses a domain name for trie insertion/lookup.
// Examples:
//   - "www.example.com" -> ["com", "example", "www"]
//   - "*.example.com"   -> ["com", "example", "*"]
//   - "*"               -> ["*"]
func reverseDomain(domain string) []string {
	if domain == "" {
		return nil
	}
	parts := strings.Split(domain, ".")
	// Reverse in place
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

// calculatePriority determines the specificity of a host pattern.
// Higher values indicate more specific patterns that should match first.
//
// Priority factors (in order of importance):
//  1. Exact matches (no wildcards) get highest priority
//  2. Longer patterns are more specific
//  3. Each wildcard reduces priority
func calculatePriority(pattern string) int {
	if pattern == "" {
		return -1
	}

	priority := 0

	// Exact matches (no wildcards) get high base priority
	hasWildcard := strings.ContainsAny(pattern, "*?")
	if !hasWildcard {
		priority += 10000
	}

	// Longer patterns are more specific (each character adds 10)
	priority += len(pattern) * 10

	// Each wildcard character reduces priority significantly
	wildcardCount := strings.Count(pattern, "*") + strings.Count(pattern, "?")
	priority -= wildcardCount * 1000

	return priority
}

// isWildcardSegment returns true if the segment contains wildcard characters.
func isWildcardSegment(segment string) bool {
	return strings.ContainsAny(segment, "*?")
}

// add inserts a host pattern into the trie.
// If a pattern already exists at the same node, the higher priority one is kept.
func (dt *domainTrie) add(host *Host) {
	if host == nil || host.Host == "" {
		return
	}

	dt.mu.Lock()
	defer dt.mu.Unlock()

	pattern := host.Host
	parts := reverseDomain(pattern)
	if len(parts) == 0 {
		return
	}

	current := dt.root
	for _, part := range parts {
		if isWildcardSegment(part) {
			// Wildcard segments share a single child node
			if current.wildcardChild == nil {
				current.wildcardChild = &domainTrieNode{
					children: make(map[string]*domainTrieNode),
				}
			}
			current = current.wildcardChild
		} else {
			// Exact segments get their own child nodes
			if current.children[part] == nil {
				current.children[part] = &domainTrieNode{
					children: make(map[string]*domainTrieNode),
				}
			}
			current = current.children[part]
		}
	}

	// Store host at terminal node (higher priority wins)
	newPriority := calculatePriority(pattern)
	existingPriority := calculatePriority(current.pattern)
	if current.host == nil || newPriority > existingPriority {
		current.host = host
		current.pattern = pattern
	}
}

// remove removes a host pattern from the trie.
// It also cleans up empty nodes to prevent memory leaks.
func (dt *domainTrie) remove(host *Host) {
	if host == nil || host.Host == "" {
		return
	}

	dt.mu.Lock()
	defer dt.mu.Unlock()

	pattern := host.Host
	parts := reverseDomain(pattern)
	if len(parts) == 0 {
		return
	}

	// Track the path for cleanup
	type pathEntry struct {
		node   *domainTrieNode
		parent *domainTrieNode
		key    string // empty for wildcardChild
	}

	path := make([]pathEntry, 0, len(parts)+1)
	current := dt.root
	path = append(path, pathEntry{node: current, parent: nil, key: ""})

	for _, part := range parts {
		var next *domainTrieNode
		var key string

		if isWildcardSegment(part) {
			next = current.wildcardChild
			key = ""
		} else {
			next = current.children[part]
			key = part
		}

		if next == nil {
			return // Pattern not found
		}

		path = append(path, pathEntry{node: next, parent: current, key: key})
		current = next
	}

	// Only remove if this is the exact host we're looking for
	if current.host != host {
		return
	}

	current.host = nil
	current.pattern = ""

	// Clean up empty nodes (traverse backwards, skip root)
	for i := len(path) - 1; i > 0; i-- {
		entry := path[i]
		node := entry.node

		// Stop if node still has content
		if node.host != nil || len(node.children) > 0 || node.wildcardChild != nil {
			break
		}

		// Remove from parent
		parent := entry.parent
		if entry.key == "" {
			parent.wildcardChild = nil
		} else {
			delete(parent.children, entry.key)
		}
	}
}

// match finds the best matching host for a given domain.
// Returns nil if no match is found.
func (dt *domainTrie) match(domain string, complexPatterns []*Host) *Host {
	if domain == "" {
		return nil
	}

	dt.mu.RLock()
	defer dt.mu.RUnlock()

	parts := reverseDomain(domain)
	if len(parts) == 0 {
		return nil
	}

	// Find all matches from the trie
	var bestMatch *Host
	bestPriority := minPriority

	dt.findMatches(parts, 0, dt.root, &bestMatch, &bestPriority)

	// Check complex patterns (fallback for patterns that don't fit the trie)
	for _, host := range complexPatterns {
		if matched, err := filepath.Match(host.Host, domain); matched && err == nil {
			priority := calculatePriority(host.Host)
			if priority > bestPriority {
				bestMatch = host
				bestPriority = priority
			}
		}
	}

	return bestMatch
}

// findMatches recursively searches the trie for all matching hosts.
// It updates bestMatch and bestPriority in place to avoid allocations.
func (dt *domainTrie) findMatches(parts []string, depth int, node *domainTrieNode, bestMatch **Host, bestPriority *int) {
	if node == nil {
		return
	}

	// Base case: consumed all domain parts
	if depth >= len(parts) {
		if node.host != nil {
			priority := calculatePriority(node.pattern)
			if priority > *bestPriority {
				*bestMatch = node.host
				*bestPriority = priority
			}
		}
		return
	}

	currentPart := parts[depth]

	// Try exact match first (most specific)
	exactMatchFound := false
	if child, ok := node.children[currentPart]; ok {
		prevBest := *bestMatch
		dt.findMatches(parts, depth+1, child, bestMatch, bestPriority)
		// Check if exact path found a match (only if it actually improved the match)
		exactMatchFound = *bestMatch != nil && *bestMatch != prevBest
	}

	// Try wildcard match only if exact path didn't find anything
	// This ensures deeper exact matches take precedence over shallower wildcards
	if !exactMatchFound && node.wildcardChild != nil {
		dt.findMatches(parts, depth+1, node.wildcardChild, bestMatch, bestPriority)
	}

	// Check if current node can match remaining parts (for patterns like "*" or "*.com")
	// Only consider if no better match was found from children
	if *bestMatch == nil && node.host != nil {
		// Verify this is a wildcard pattern that can match remaining parts
		if isWildcardPattern(node.pattern) {
			priority := calculatePriority(node.pattern)
			if priority > *bestPriority {
				*bestMatch = node.host
				*bestPriority = priority
			}
		}
	}
}

// isWildcardPattern returns true if the pattern contains wildcards
// that can match variable-length domain parts.
func isWildcardPattern(pattern string) bool {
	return strings.ContainsAny(pattern, "*?")
}

// isComplexPattern determines if a pattern is too complex for the trie.
// Complex patterns have wildcards in positions that don't align with domain segments.
//
// Simple patterns (handled by trie):
//   - Exact: "www.example.com"
//   - Prefix wildcard: "*.example.com"
//   - Suffix wildcard: "example.*"
//   - Catch-all: "*"
//
// Complex patterns (fallback to filepath.Match):
//   - Middle wildcards: "example.*.com"
//   - Embedded wildcards: "*example.com", "www*.example.com"
func isComplexPattern(pattern string) bool {
	if pattern == "" || pattern == "*" {
		return false
	}

	parts := strings.Split(pattern, ".")

	for i, part := range parts {
		if !strings.ContainsAny(part, "*?") {
			continue
		}

		// Wildcards in middle segments are complex
		if i > 0 && i < len(parts)-1 {
			return true
		}

		// Partial wildcards (not just "*" or "?") are complex
		// e.g., "*example" or "www*" within a segment
		if part != "*" && part != "?" {
			return true
		}
	}

	return false
}
