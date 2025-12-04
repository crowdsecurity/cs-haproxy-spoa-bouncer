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

// Built-in remediation constants (for convenience)
// Initialized to nil, will be set in init()
var (
	Allow   Remediation
	Unknown Remediation
	Captcha Remediation
	Ban     Remediation
)

//nolint:gochecknoinits // init() is required to initialize package-level vars after weights are set
func init() {
	// Initialize built-in remediations with default weights
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	// Set weights FIRST before creating strings
	globalRegistry.weights["allow"] = WeightAllow
	globalRegistry.weights["unknown"] = WeightUnknown
	globalRegistry.weights["captcha"] = WeightCaptcha
	globalRegistry.weights["ban"] = WeightBan

	// Pre-create deduplicated strings for built-in remediations
	// Must create new string variables for each to avoid pointer aliasing
	allowStr := "allow"
	unknownStr := "unknown"
	captchaStr := "captcha"
	banStr := "ban"

	globalRegistry.strings["allow"] = &allowStr
	globalRegistry.strings["unknown"] = &unknownStr
	globalRegistry.strings["captcha"] = &captchaStr
	globalRegistry.strings["ban"] = &banStr

	// Now initialize the package-level vars directly (we already hold the lock)
	// This avoids deadlock since New() would try to acquire the lock again
	Allow = Remediation{name: &allowStr, weight: WeightAllow}
	Unknown = Remediation{name: &unknownStr, weight: WeightUnknown}
	Captcha = Remediation{name: &captchaStr, weight: WeightCaptcha}
	Ban = Remediation{name: &banStr, weight: WeightBan}
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

	// Read weight from registry (may have been set in init() or SetWeight())
	weight, ok := globalRegistry.weights[name]
	if !ok {
		// Weight not found, default to Unknown
		weight = WeightUnknown
	}
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

// IsHigher returns true if r has a higher weight than other
func (r Remediation) IsHigher(other Remediation) bool {
	return r.weight > other.weight
}

// IsLower returns true if r has a lower weight than other
func (r Remediation) IsLower(other Remediation) bool {
	return r.weight < other.weight
}

// IsEqual returns true if r has the same weight as other
func (r Remediation) IsEqual(other Remediation) bool {
	return r.weight == other.weight
}

// IsWeighted returns true if r is not Allow (has weight > Allow)
// This is useful for checking if a remediation should be applied
func (r Remediation) IsWeighted() bool {
	return r.weight > WeightAllow
}

// FromString creates a Remediation from a string (alias for New for backward compatibility)
func FromString(s string) Remediation {
	return New(s)
}

// IsZero returns true if the remediation is zero-valued
func (r Remediation) IsZero() bool {
	return r.name == nil
}
