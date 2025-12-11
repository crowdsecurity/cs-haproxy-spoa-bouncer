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
type Remediation string

// Built-in remediation constants
const (
	Allow   Remediation = "allow"
	Unknown Remediation = "unknown"
	Captcha Remediation = "captcha"
	Ban     Remediation = "ban"
)

// registry manages remediation weights
type registry struct {
	mu      sync.RWMutex
	weights map[string]int // Maps remediation name to its weight
}

var globalRegistry = &registry{
	weights: make(map[string]int),
}

//nolint:gochecknoinits // init() is required to initialize default weights
func init() {
	// Initialize built-in remediations with default weights
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	globalRegistry.weights["allow"] = WeightAllow
	globalRegistry.weights["unknown"] = WeightUnknown
	globalRegistry.weights["captcha"] = WeightCaptcha
	globalRegistry.weights["ban"] = WeightBan
}

// SetWeight sets a custom weight for a remediation (for configuration)
func SetWeight(name string, weight int) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	globalRegistry.weights[name] = weight
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

// LoadWeights loads weights for multiple remediations at once (for startup initialization)
func LoadWeights(weights map[string]int) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	for name, weight := range weights {
		globalRegistry.weights[name] = weight
	}
}

// New creates a new Remediation from a string.
func New(name string) Remediation {
	return Remediation(name)
}

// String returns the remediation name
func (r Remediation) String() string {
	if r == "" {
		return "allow" // Default fallback
	}
	return string(r)
}

// Compare returns:
// - negative if a < b
// - zero if a == b
// - positive if a > b
func Compare(a, b Remediation) int {
	weightA := GetWeight(a.String())
	weightB := GetWeight(b.String())
	return weightA - weightB
}

// IsHigher returns true if a has a higher weight than b
func IsHigher(a, b Remediation) bool {
	return Compare(a, b) > 0
}

// IsLower returns true if a has a lower weight than b
func IsLower(a, b Remediation) bool {
	return Compare(a, b) < 0
}

// IsEqual returns true if a represents the same remediation as b.
// This compares the remediation names (strings).
func IsEqual(a, b Remediation) bool {
	return a == b
}

// HasSameWeight returns true if a has the same weight as b.
// This is useful for checking if two different remediations have the same priority.
// Note: Two remediations with the same weight will be compared by name (alphabetical)
// as a tie-breaker when determining priority.
func HasSameWeight(a, b Remediation) bool {
	return Compare(a, b) == 0
}

// IsWeighted returns true if r is not Allow (has weight > Allow)
// This is useful for checking if a remediation should be applied
func IsWeighted(r Remediation) bool {
	return GetWeight(r.String()) > WeightAllow
}

// FromString creates a Remediation from a string (alias for New for backward compatibility)
func FromString(s string) Remediation {
	return New(s)
}

// IsZero returns true if the remediation is zero-valued
func (r Remediation) IsZero() bool {
	return r == ""
}
