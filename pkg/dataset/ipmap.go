package dataset

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

// ipEntry wraps RemediationMap with an atomic pointer for lock-free reads.
// This ensures SPOA handlers never block when checking IPs, even during updates.
// - Readers load the atomic pointer (instant, never blocks)
// - Writers clone, modify, and swap (readers see old or new, never partial state)
type ipEntry struct {
	data atomic.Pointer[RemediationMap]
}

// IPMap provides efficient storage for individual IP addresses.
// Uses sync.Map with atomic pointers per entry for lock-free reads.
// This is much more memory efficient than BART for individual IPs
// since it doesn't require the radix trie overhead.
//
// Concurrency model:
// - Reads are completely lock-free (atomic pointer load)
// - Writes use copy-on-write (clone, modify, swap)
// - Single-writer, multiple-reader: no mutex needed
// - SPOA handlers never block, even during batch updates
type IPMap struct {
	// IPv4 addresses stored by their 4-byte representation
	ipv4 sync.Map // map[netip.Addr]*ipEntry
	// IPv6 addresses stored by their 16-byte representation
	ipv6   sync.Map // map[netip.Addr]*ipEntry
	logger *log.Entry
	// Counters for monitoring
	ipv4Count atomic.Int64
	ipv6Count atomic.Int64
}

// NewIPMap creates a new IPMap for storing individual IP addresses
func NewIPMap(logAlias string) *IPMap {
	return &IPMap{
		logger: log.WithField("alias", logAlias),
	}
}

// IPAddOp represents an add operation for an individual IP
type IPAddOp struct {
	IP     netip.Addr
	Origin string
	R      string // Remediation name as string
	IPType string
}

// IPRemoveOp represents a remove operation for an individual IP
type IPRemoveOp struct {
	IP     netip.Addr
	R      string // Remediation name as string
	Origin string
	IPType string
}

// AddBatch adds multiple IPs to the map
// Safe for single-writer, multiple-reader scenarios
func (m *IPMap) AddBatch(operations []IPAddOp) {
	if len(operations) == 0 {
		return
	}

	for _, op := range operations {
		m.add(op)
	}
}

// add adds a single IP
func (m *IPMap) add(op IPAddOp) {
	var valueLog *log.Entry
	if m.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = m.logger.WithField("ip", op.IP.String()).WithField("remediation", op.R)
		valueLog.Trace("adding IP to map")
	}

	// Select the appropriate map based on IP version
	ipMap := &m.ipv4
	counter := &m.ipv4Count
	if op.IP.Is6() {
		ipMap = &m.ipv6
		counter = &m.ipv6Count
	}

	// Try to load existing entry first
	if existing, ok := ipMap.Load(op.IP); ok {
		if entry, ok := existing.(*ipEntry); ok {
			current := entry.data.Load()
			var newData RemediationMap
			if current != nil && len(*current) > 0 {
				// Clone only if map has entries (copy-on-write for readers)
				newData = current.Clone()
			} else {
				// Empty or nil - no need to clone, just create new map
				newData = make(RemediationMap)
			}
			newData.Add(valueLog, remediation.FromString(op.R), op.Origin)
			entry.data.Store(&newData)
			return
		}
	}

	// Create new entry with data
	// Store directly (no LoadOrStore race needed since application uses single writer)
	newData := make(RemediationMap)
	newData.Add(valueLog, remediation.FromString(op.R), op.Origin)
	entry := &ipEntry{}
	entry.data.Store(&newData)
	ipMap.Store(op.IP, entry)
	counter.Add(1)
}

// RemoveBatch removes multiple IPs from the map
// Returns a slice of pointers to successfully removed operations (nil for failures)
// Safe for single-writer, multiple-reader scenarios
func (m *IPMap) RemoveBatch(operations []IPRemoveOp) []*IPRemoveOp {
	if len(operations) == 0 {
		return nil
	}

	results := make([]*IPRemoveOp, len(operations))
	for i, op := range operations {
		if m.remove(op) {
			results[i] = &operations[i]
		}
	}
	return results
}

// remove removes a single IP
func (m *IPMap) remove(op IPRemoveOp) bool {
	var valueLog *log.Entry
	if m.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = m.logger.WithField("ip", op.IP.String()).WithField("remediation", op.R)
		valueLog.Trace("removing IP from map")
	}

	// Select the appropriate map based on IP version
	ipMap := &m.ipv4
	counter := &m.ipv4Count
	if op.IP.Is6() {
		ipMap = &m.ipv6
		counter = &m.ipv6Count
	}

	existing, ok := ipMap.Load(op.IP)
	if !ok {
		if valueLog != nil {
			valueLog.Trace("IP not found in map")
		}
		return false
	}

	entry, ok := existing.(*ipEntry)
	if !ok {
		return false
	}

	current := entry.data.Load()
	if current == nil {
		if valueLog != nil {
			valueLog.Trace("IP entry has no data")
		}
		return false
	}

	// Check if the remediation exists with the matching origin before removing
	// This prevents removing decisions when the origin has been overwritten (e.g., by CAPI)
	if !current.HasRemediationWithOrigin(remediation.FromString(op.R), op.Origin) {
		// Origin doesn't match - this decision was likely overwritten by another origin
		// Don't remove it, as it's not the decision we're trying to delete
		if valueLog != nil {
			r := remediation.FromString(op.R)
			storedOrigin, exists := (*current)[r]
			if exists {
				valueLog.Tracef("remediation exists but origin mismatch (stored: %s, requested: %s), skipping removal", storedOrigin, op.Origin)
			} else {
				valueLog.Tracef("remediation not found, skipping removal")
			}
		}
		return false
	}

	// Always clone for copy-on-write, even if this is the only remediation
	// This ensures consistency and handles edge cases where the same origin might
	// change remediation types (e.g., ban -> captcha) in separate stream messages
	newData := current.Clone()

	// Remove returns an error if remediation doesn't exist (duplicate delete)
	// We already checked origin above, so this should succeed
	err := newData.Remove(valueLog, remediation.FromString(op.R))
	if errors.Is(err, ErrRemediationNotFound) {
		// This shouldn't happen since we checked above, but handle it gracefully
		if valueLog != nil {
			valueLog.Trace("remediation not found after origin check, duplicate delete")
		}
		return false
	}

	// Check if entry is now empty after removal
	if newData.IsEmpty() {
		// No remediations left - delete the IP entry entirely
		ipMap.Delete(op.IP)
		counter.Add(-1)
		if valueLog != nil {
			valueLog.Trace("removed IP entirely")
		}
	} else {
		// Still has other remediations - update the entry with the modified map
		entry.data.Store(&newData)
		if valueLog != nil {
			valueLog.Trace("removed remediation from IP")
		}
	}

	return true
}

// Contains checks if an IP address exists in the map
// Returns the remediation and origin if found
// This method is completely lock-free - SPOA handlers never block
func (m *IPMap) Contains(ip netip.Addr) (remediation.Remediation, string, bool) {
	var valueLog *log.Entry
	if m.logger.Logger.IsLevelEnabled(log.TraceLevel) {
		valueLog = m.logger.WithField("ip", ip.String())
		valueLog.Trace("checking IP in map")
	}

	// Select the appropriate map based on IP version
	ipMap := &m.ipv4
	if ip.Is6() {
		ipMap = &m.ipv6
	}

	existing, ok := ipMap.Load(ip)
	if !ok {
		if valueLog != nil {
			valueLog.Trace("IP not found in map")
		}
		return remediation.Allow, "", false
	}

	entry, ok := existing.(*ipEntry)
	if !ok {
		return remediation.Allow, "", false
	}

	// Lock-free read via atomic pointer
	data := entry.data.Load()
	if data == nil {
		return remediation.Allow, "", false
	}

	r, origin := data.GetRemediationAndOrigin()
	if valueLog != nil {
		valueLog.Tracef("found IP with remediation: %s", r.String())
	}
	return r, origin, true
}

// Count returns the number of IPs stored (for monitoring)
func (m *IPMap) Count() (ipv4 int64, ipv6 int64) {
	return m.ipv4Count.Load(), m.ipv6Count.Load()
}

// HasRemediation checks if an IP has a specific remediation with a specific origin.
// Returns true if the IP exists and has the given remediation with the given origin.
func (m *IPMap) HasRemediation(ip netip.Addr, r remediation.Remediation, origin string) bool {
	// Select the appropriate map based on IP version
	ipMap := &m.ipv4
	if ip.Is6() {
		ipMap = &m.ipv6
	}

	existing, ok := ipMap.Load(ip)
	if !ok {
		return false
	}

	entry, ok := existing.(*ipEntry)
	if !ok {
		return false
	}

	// Lock-free read via atomic pointer
	data := entry.data.Load()
	if data == nil {
		return false
	}

	return data.HasRemediationWithOrigin(r, origin)
}
