# Host Trie Implementation

## Overview

This document describes the trie-based optimization for host pattern matching, designed to scale efficiently for MSSP deployments with hundreds or thousands of host configurations.

## Problem Statement

The original implementation stored hosts in a slice and used linear search with `filepath.Match()` for each request. This approach has O(n) complexity and doesn't scale well for large numbers of hosts.

## Solution: Reverse Domain Trie

We implemented a **reverse domain trie** that provides O(m) lookup complexity where m is the depth of the domain (typically 2-4 levels), independent of the total number of hosts.

### How It Works

#### Domain Reversal

Domains are reversed before insertion to enable efficient prefix matching:
- `www.example.com` → `["com", "example", "www"]`
- `*.example.com` → `["com", "example", "*"]`
- `*` → `["*"]`

This allows patterns like `*.example.com` to share the common `com → example` path with other patterns for the same domain.

#### Trie Structure

```
root
├── com (exact)
│   └── example (exact)
│       ├── www (exact) → Host: www.example.com
│       └── * (wildcard) → Host: *.example.com
└── * (wildcard) → Host: * (catch-all)
```

#### Matching Algorithm

The `findMatches` function traverses the trie recursively:

1. **Exact match first**: Try to match the current domain segment exactly
2. **Wildcard fallback**: If no exact match found, try the wildcard child
3. **Priority comparison**: When multiple matches are possible, the highest priority wins

### Priority System

Priority determines which pattern wins when multiple patterns could match:

| Factor | Impact |
|--------|--------|
| Exact match (no wildcards) | +10,000 |
| Pattern length | +10 per character |
| Each wildcard character | -1,000 |

Examples:
- `www.example.com` → 10,000 + 150 = **10,150**
- `*.example.com` → 0 + 130 - 1,000 = **-870**
- `*` → 0 + 10 - 1,000 = **-990**

### Pattern Classification

**Simple patterns** (handled efficiently by trie):
- Exact: `www.example.com`
- Prefix wildcard: `*.example.com`
- Suffix wildcard: `example.*`
- Catch-all: `*`

**Complex patterns** (fallback to `filepath.Match`):
- Middle wildcards: `example.*.com`
- Partial wildcards: `*example.com`, `www*.example.com`

## Performance Characteristics

| Operation | Complexity |
|-----------|------------|
| Lookup | O(m) where m = domain depth |
| Insert | O(m) |
| Delete | O(m) |
| Space | O(n × m) where n = number of hosts |

For typical domains (3-4 segments), lookup is effectively O(1) regardless of the number of hosts stored.

## API

The implementation is transparent - no changes needed to existing code:

```go
manager := host.NewManager(logger)
manager.addHost(host)           // Adds to trie or complexPatterns
manager.removeHost(host)        // Removes from trie
matched := manager.MatchFirstHost("api.example.com")  // Uses trie for lookup
```

## Key Improvements (v2)

1. **Removed dead code**: Eliminated unused `getAllHosts()` and `collectHosts()` functions
2. **Fixed priority bug**: Priority comparison now uses `math.MinInt` as the initial value
3. **Zero allocations in hot path**: `findMatches` uses pointers instead of returning slices
4. **Better documentation**: Comprehensive comments explaining the algorithm
5. **Cleaner node structure**: Removed unused `priority` field from nodes (calculated on demand)
6. **Edge case handling**: Proper nil/empty checks throughout

## Testing

The implementation includes comprehensive tests covering:
- Single host matching
- Multiple hosts with priority ordering
- Wildcard patterns (prefix, suffix, catch-all)
- Complex wildcard patterns
- Host removal
- Cache behavior
- Edge cases (no hosts, no match)
