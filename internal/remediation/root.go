package remediation

import (
	"sync"
)

// Default weights for built-in remediations
// Allow=0, Unknown=1, then expand others to allow custom remediations to slot in between
const (
	WeightAllow   = 0
	WeightUnknown = 1
	WeightCaptcha = 10
	WeightBan     = 20
)

// Remediation represents a remediation type as a string
// We use string pointers for deduplication to reduce allocations
type Remediation struct {
	name   *string // Pointer to deduplicated string
	weight int     // Weight for comparison (higher = more severe)
}

// registry manages deduplicated remediation strings and their weights
type registry struct {
	mu      sync.RWMutex
	strings map[string]*string // Maps string to its deduplicated pointer
	weights map[string]int     // Maps remediation name to its weight
}

var globalRegistry = &registry{
	strings: make(map[string]*string),
	weights: make(map[string]int),
}

func init() {
	// Initialize built-in remediations with default weights
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	globalRegistry.weights["allow"] = WeightAllow
	globalRegistry.weights["unknown"] = WeightUnknown
	globalRegistry.weights["captcha"] = WeightCaptcha
	globalRegistry.weights["ban"] = WeightBan

	// Pre-create deduplicated strings for built-in remediations
	for name := range globalRegistry.weights {
		deduped := name
		globalRegistry.strings[name] = &deduped
	}
}

// SetWeight sets a custom weight for a remediation (for configuration)
func SetWeight(name string, weight int) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	globalRegistry.weights[name] = weight
	// Ensure deduplicated string exists
	if _, exists := globalRegistry.strings[name]; !exists {
		deduped := name
		globalRegistry.strings[name] = &deduped
	}
}

// GetWeight returns the weight for a remediation name
func GetWeight(name string) int {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	if weight, exists := globalRegistry.weights[name]; exists {
		return weight
	}
	// Default to Unknown weight for unknown remediations
	return WeightUnknown
}

// Built-in remediation constants (for convenience)
var (
	Allow   = New("allow")
	Unknown = New("unknown")
	Captcha = New("captcha")
	Ban     = New("ban")
)

// New creates a new Remediation from a string
// Uses deduplicated string pointers to reduce allocations
func New(name string) Remediation {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	// Get or create deduplicated string pointer
	deduped, exists := globalRegistry.strings[name]
	if !exists {
		// Create new deduplicated string
		deduped = &name
		globalRegistry.strings[name] = deduped
		// Set default weight if not configured
		if _, hasWeight := globalRegistry.weights[name]; !hasWeight {
			globalRegistry.weights[name] = WeightUnknown
		}
	}

	weight := globalRegistry.weights[name]
	return Remediation{
		name:   deduped,
		weight: weight,
	}
}

// String returns the remediation name
func (r Remediation) String() string {
	if r.name == nil {
		return "allow" // Default fallback
	}
	return *r.name
}

// Weight returns the weight of the remediation
func (r Remediation) Weight() int {
	return r.weight
}

// Compare returns:
// - negative if r < other
// - zero if r == other
// - positive if r > other
func (r Remediation) Compare(other Remediation) int {
	return r.weight - other.weight
}

// FromString creates a Remediation from a string (alias for New for backward compatibility)
func FromString(s string) Remediation {
	return New(s)
}

// IsZero returns true if the remediation is zero-valued
func (r Remediation) IsZero() bool {
	return r.name == nil
}
