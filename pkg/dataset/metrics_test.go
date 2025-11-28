package dataset

import (
	"net/netip"
	"testing"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to get the current metric value for active decisions
func getActiveDecisionsMetric(origin, ipType, scope string) float64 {
	labels := prometheus.Labels{
		"origin":  origin,
		"ip_type": ipType,
		"scope":   scope,
	}
	return testutil.ToFloat64(metrics.TotalActiveDecisions.With(labels))
}

func TestMetrics_IPMap_AddAndDelete(t *testing.T) {
	dataSet := New()

	origin := "test-origin"
	ipType := "ipv4"
	scope := "ip"

	t.Run("Add single decision increments metric", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.1"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(decisions)
		after := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(decisions))+before, after, 0.001, "metric should increment by number of decisions added")
	})

	t.Run("Delete existing decision decrements metric", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.1"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Remove(decisions)
		after := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, before-float64(len(decisions)), after, 0.001, "metric should decrement by number of decisions removed")
	})

	t.Run("Duplicate delete does not decrement metric", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.1"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Remove(decisions) // Delete again (should be duplicate)
		after := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, before, after, 0.001, "metric should not change on duplicate delete")
	})

	t.Run("Multiple IPs increment metrics correctly", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.1"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.2"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.3"),
				Type:   ptr.Of("captcha"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(decisions)
		after := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(decisions))+before, after, 0.001, "metric should increment by number of decisions added")
	})

	t.Run("Same IP different remediation counts as separate decisions", func(t *testing.T) {
		banDecision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.10"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(banDecision)
		afterBan := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(banDecision))+before, afterBan, 0.001, "metric should increment after adding ban")

		captchaDecision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.10"),
				Type:   ptr.Of("captcha"),
				Origin: ptr.Of(origin),
			},
		}

		dataSet.Add(captchaDecision)
		afterCaptcha := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(captchaDecision))+afterBan, afterCaptcha, 0.001, "metric should increment after adding captcha for same IP")
	})

	//nolint:dupl // Similar test structure for different data types is acceptable
	t.Run("Overwriting decision with same IP and remediation updates metric correctly", func(t *testing.T) {
		differentOrigin := "different-origin"
		decision1 := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.20"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(decision1)
		afterFirst := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(decision1))+before, afterFirst, 0.001, "metric should increment after first add")

		decision2 := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.20"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(differentOrigin),
			},
		}

		beforeDiffOrigin := getActiveDecisionsMetric(differentOrigin, ipType, scope)
		dataSet.Add(decision2)

		afterSecond := getActiveDecisionsMetric(origin, ipType, scope)
		afterSecondDiffOrigin := getActiveDecisionsMetric(differentOrigin, ipType, scope)

		assert.InDelta(t, afterFirst-float64(len(decision2)), afterSecond, 0.001, "original origin metric should decrement when overwritten")
		assert.InDelta(t, float64(len(decision2))+beforeDiffOrigin, afterSecondDiffOrigin, 0.001, "new origin metric should increment")
	})

	t.Run("IPv6 decision increments metric correctly", func(t *testing.T) {
		decision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("2001:db8::1"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, "ipv6", scope)
		dataSet.Add(decision)
		after := getActiveDecisionsMetric(origin, "ipv6", scope)
		assert.InDelta(t, float64(len(decision))+before, after, 0.001, "metric should increment by number of decisions added")
	})
}

func TestMetrics_BartRangeSet_AddAndDelete(t *testing.T) {
	dataSet := New()

	origin := "test-origin-range"
	ipType := "ipv4"
	scope := "range"

	t.Run("Add single range decision increments metric", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("192.168.1.0/24"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(decisions)
		after := getActiveDecisionsMetric(origin, ipType, scope)

		assert.InDelta(t, float64(len(decisions))+before, after, 0.001, "metric should increment by number of decisions added")
	})

	t.Run("Delete existing range decision decrements metric", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("192.168.1.0/24"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Remove(decisions)
		after := getActiveDecisionsMetric(origin, ipType, scope)

		assert.InDelta(t, before-float64(len(decisions)), after, 0.001, "metric should decrement by number of decisions removed")
	})

	t.Run("Duplicate delete does not decrement metric", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("192.168.1.0/24"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Remove(decisions) // Delete again (should be duplicate)
		after := getActiveDecisionsMetric(origin, ipType, scope)

		assert.InDelta(t, before, after, 0.001, "metric should not change on duplicate delete")
	})

	t.Run("Multiple ranges increment metrics correctly", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("10.0.0.0/8"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("172.16.0.0/12"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("192.168.0.0/16"),
				Type:   ptr.Of("captcha"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(decisions)
		after := getActiveDecisionsMetric(origin, ipType, scope)

		assert.InDelta(t, float64(len(decisions))+before, after, 0.001, "metric should increment by number of decisions added")
	})

	t.Run("Same prefix different remediation counts as separate decisions", func(t *testing.T) {
		// Add ban decision
		banDecision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("192.168.2.0/24"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(banDecision)
		afterBan := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(banDecision))+before, afterBan, 0.001, "metric should increment after adding ban")

		// Add captcha decision for same prefix
		captchaDecision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("192.168.2.0/24"),
				Type:   ptr.Of("captcha"),
				Origin: ptr.Of(origin),
			},
		}

		dataSet.Add(captchaDecision)
		afterCaptcha := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(captchaDecision))+afterBan, afterCaptcha, 0.001, "metric should increment after adding captcha for same prefix")
	})

	t.Run("IPv6 range decision increments metric correctly", func(t *testing.T) {
		decision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("2001:db8::/32"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, "ipv6", scope)
		dataSet.Add(decision)
		after := getActiveDecisionsMetric(origin, "ipv6", scope)

		assert.InDelta(t, float64(len(decision))+before, after, 0.001, "metric should increment by number of decisions added")
	})

	//nolint:dupl // Similar test structure for different data types is acceptable
	t.Run("Overwriting range decision with same prefix and remediation updates metric correctly", func(t *testing.T) {
		// Add decision with first origin
		decision1 := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("192.168.10.0/24"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(decision1)
		afterFirst := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(decision1))+before, afterFirst, 0.001, "metric should increment after first add")

		// Add same decision again with different origin (overwrites the data)
		decision2 := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("192.168.10.0/24"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of("different-origin"), // Different origin
			},
		}

		beforeSecondDiffOrigin := getActiveDecisionsMetric("different-origin", ipType, scope)

		dataSet.Add(decision2)

		afterSecond := getActiveDecisionsMetric(origin, ipType, scope)
		afterSecondDiffOrigin := getActiveDecisionsMetric("different-origin", ipType, scope)

		// Original origin metric should be decremented (decision was overwritten)
		assert.InDelta(t, afterFirst-float64(len(decision2)), afterSecond, 0.001, "original origin metric should decrement when overwritten")
		// New origin gets incremented
		assert.InDelta(t, float64(len(decision2))+beforeSecondDiffOrigin, afterSecondDiffOrigin, 0.001, "new origin metric should increment")
	})
}

func TestMetrics_CNSet_AddAndDelete(t *testing.T) {
	dataSet := New()

	origin := "test-origin-cn"
	ipType := "" // Country decisions have empty ip_type
	scope := "country"

	t.Run("Add single country decision increments metric", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("FR"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(decisions)
		after := getActiveDecisionsMetric(origin, ipType, scope)

		assert.InDelta(t, float64(len(decisions))+before, after, 0.001, "metric should increment by number of decisions added")
	})

	t.Run("Delete existing country decision decrements metric", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("FR"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Remove(decisions)
		after := getActiveDecisionsMetric(origin, ipType, scope)

		assert.InDelta(t, before-float64(len(decisions)), after, 0.001, "metric should decrement by number of decisions removed")
	})

	t.Run("Duplicate delete does not decrement metric", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("FR"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Remove(decisions) // Delete again (should be duplicate)
		after := getActiveDecisionsMetric(origin, ipType, scope)

		assert.InDelta(t, before, after, 0.001, "metric should not change on duplicate delete")
	})

	t.Run("Multiple countries increment metrics correctly", func(t *testing.T) {
		decisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("US"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("GB"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("DE"),
				Type:   ptr.Of("captcha"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(decisions)
		after := getActiveDecisionsMetric(origin, ipType, scope)

		assert.InDelta(t, float64(len(decisions))+before, after, 0.001, "metric should increment by number of decisions added")
	})

	t.Run("Same country different remediation counts as separate decisions", func(t *testing.T) {
		// Add ban decision
		banDecision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("IT"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(banDecision)
		afterBan := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(banDecision))+before, afterBan, 0.001, "metric should increment after adding ban")

		// Add captcha decision for same country
		captchaDecision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("IT"),
				Type:   ptr.Of("captcha"),
				Origin: ptr.Of(origin),
			},
		}

		dataSet.Add(captchaDecision)
		afterCaptcha := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(captchaDecision))+afterBan, afterCaptcha, 0.001, "metric should increment after adding captcha for same country")
	})

	//nolint:dupl // Similar test structure for different data types is acceptable
	t.Run("Overwriting country decision with same country and remediation updates metric correctly", func(t *testing.T) {
		// Add decision with first origin
		decision1 := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("CA"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(decision1)
		afterFirst := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(decision1))+before, afterFirst, 0.001, "metric should increment after first add")

		// Add same decision again with different origin (overwrites the data)
		decision2 := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("CA"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of("different-origin"), // Different origin
			},
		}

		beforeSecondDiffOrigin := getActiveDecisionsMetric("different-origin", ipType, scope)

		dataSet.Add(decision2)

		afterSecond := getActiveDecisionsMetric(origin, ipType, scope)
		afterSecondDiffOrigin := getActiveDecisionsMetric("different-origin", ipType, scope)

		// Original origin metric should be decremented (decision was overwritten)
		assert.InDelta(t, afterFirst-float64(len(decision2)), afterSecond, 0.001, "original origin metric should decrement when overwritten")
		// New origin gets incremented
		assert.InDelta(t, float64(len(decision2))+beforeSecondDiffOrigin, afterSecondDiffOrigin, 0.001, "new origin metric should increment")
	})
}

func TestMetrics_MixedOperations(t *testing.T) {
	dataSet := New()

	origin := "test-origin-mixed"

	t.Run("Mixed IP, range, and country operations", func(t *testing.T) {
		// Add one of each type
		addDecisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.100"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("10.10.0.0/16"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("JP"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		beforeIP := getActiveDecisionsMetric(origin, "ipv4", "ip")
		beforeRange := getActiveDecisionsMetric(origin, "ipv4", "range")
		beforeCountry := getActiveDecisionsMetric(origin, "", "country")

		dataSet.Add(addDecisions)

		afterIP := getActiveDecisionsMetric(origin, "ipv4", "ip")
		afterRange := getActiveDecisionsMetric(origin, "ipv4", "range")
		afterCountry := getActiveDecisionsMetric(origin, "", "country")

		assert.InDelta(t, beforeIP+1, afterIP, 0.001, "IP metric should increment")
		assert.InDelta(t, beforeRange+1, afterRange, 0.001, "Range metric should increment")
		assert.InDelta(t, beforeCountry+1, afterCountry, 0.001, "Country metric should increment")

		// Remove all of them
		removeDecisions := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.1.100"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("10.10.0.0/16"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("JP"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		beforeRemoveIP := getActiveDecisionsMetric(origin, "ipv4", "ip")
		beforeRemoveRange := getActiveDecisionsMetric(origin, "ipv4", "range")
		beforeRemoveCountry := getActiveDecisionsMetric(origin, "", "country")

		dataSet.Remove(removeDecisions)

		afterRemoveIP := getActiveDecisionsMetric(origin, "ipv4", "ip")
		afterRemoveRange := getActiveDecisionsMetric(origin, "ipv4", "range")
		afterRemoveCountry := getActiveDecisionsMetric(origin, "", "country")

		assert.InDelta(t, beforeRemoveIP-1, afterRemoveIP, 0.001, "IP metric should decrement")
		assert.InDelta(t, beforeRemoveRange-1, afterRemoveRange, 0.001, "Range metric should decrement")
		assert.InDelta(t, beforeRemoveCountry-1, afterRemoveCountry, 0.001, "Country metric should decrement")
	})
}

func TestMetrics_LiveDecisionsCount(t *testing.T) {
	dataSet := New()

	origin := "test-origin-live"
	ipType := "ipv4"
	scope := "ip"

	t.Run("Live decisions count is accurate after adds and deletes", func(t *testing.T) {
		// Add 5 decisions
		addDecisions := models.GetDecisionsResponse{
			{Scope: ptr.Of("IP"), Value: ptr.Of("192.168.1.1"), Type: ptr.Of("ban"), Origin: ptr.Of(origin)},
			{Scope: ptr.Of("IP"), Value: ptr.Of("192.168.1.2"), Type: ptr.Of("ban"), Origin: ptr.Of(origin)},
			{Scope: ptr.Of("IP"), Value: ptr.Of("192.168.1.3"), Type: ptr.Of("ban"), Origin: ptr.Of(origin)},
			{Scope: ptr.Of("IP"), Value: ptr.Of("192.168.1.4"), Type: ptr.Of("ban"), Origin: ptr.Of(origin)},
			{Scope: ptr.Of("IP"), Value: ptr.Of("192.168.1.5"), Type: ptr.Of("ban"), Origin: ptr.Of(origin)},
		}

		before := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Add(addDecisions)
		afterAdd := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, float64(len(addDecisions))+before, afterAdd, 0.001, "metric should increment by number of decisions added")

		// Remove 2 decisions
		removeDecisions := models.GetDecisionsResponse{
			{Scope: ptr.Of("IP"), Value: ptr.Of("192.168.1.1"), Type: ptr.Of("ban"), Origin: ptr.Of(origin)},
			{Scope: ptr.Of("IP"), Value: ptr.Of("192.168.1.2"), Type: ptr.Of("ban"), Origin: ptr.Of(origin)},
		}

		beforeRemove := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Remove(removeDecisions)
		afterRemove := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, beforeRemove-float64(len(removeDecisions)), afterRemove, 0.001, "metric should decrement by number of decisions removed")

		// Try to remove non-existent decision (duplicate delete)
		duplicateRemove := models.GetDecisionsResponse{
			{Scope: ptr.Of("IP"), Value: ptr.Of("192.168.1.1"), Type: ptr.Of("ban"), Origin: ptr.Of(origin)},
		}

		beforeDup := getActiveDecisionsMetric(origin, ipType, scope)
		dataSet.Remove(duplicateRemove)
		afterDup := getActiveDecisionsMetric(origin, ipType, scope)
		assert.InDelta(t, beforeDup, afterDup, 0.001, "metric should not change on duplicate delete")
		assert.InDelta(t, afterRemove, afterDup, 0.001, "metric should remain at same value after duplicate delete attempt")

		// Verify the remaining 3 decisions are still there
		ip1, err := netip.ParseAddr("192.168.1.1")
		require.NoError(t, err)
		ip3, err := netip.ParseAddr("192.168.1.3")
		require.NoError(t, err)
		ip5, err := netip.ParseAddr("192.168.1.5")
		require.NoError(t, err)

		_, _, found1 := dataSet.IPMap.Contains(ip1)
		assert.False(t, found1, "192.168.1.1 should not exist")

		_, _, found3 := dataSet.IPMap.Contains(ip3)
		assert.True(t, found3, "192.168.1.3 should still exist")

		_, _, found5 := dataSet.IPMap.Contains(ip5)
		assert.True(t, found5, "192.168.1.5 should still exist")
	})
}

func TestMetrics_OriginTracking(t *testing.T) {
	dataSet := New()

	ipType := "ipv4"
	scope := "ip"

	t.Run("Different origins tracked separately", func(t *testing.T) {
		origin1 := "origin1"
		origin2 := "origin2"

		// Add decision from origin1
		decision1 := models.GetDecisionsResponse{
			{Scope: ptr.Of("IP"), Value: ptr.Of("192.168.10.1"), Type: ptr.Of("ban"), Origin: ptr.Of(origin1)},
		}

		before1 := getActiveDecisionsMetric(origin1, ipType, scope)
		before2 := getActiveDecisionsMetric(origin2, ipType, scope)

		dataSet.Add(decision1)

		after1 := getActiveDecisionsMetric(origin1, ipType, scope)
		after2 := getActiveDecisionsMetric(origin2, ipType, scope)

		assert.InDelta(t, before1+1, after1, 0.001, "origin1 metric should increment")
		assert.InDelta(t, before2, after2, 0.001, "origin2 metric should not change")

		// Add decision from origin2
		decision2 := models.GetDecisionsResponse{
			{Scope: ptr.Of("IP"), Value: ptr.Of("192.168.10.2"), Type: ptr.Of("ban"), Origin: ptr.Of(origin2)},
		}

		before1_2 := getActiveDecisionsMetric(origin1, ipType, scope)
		before2_2 := getActiveDecisionsMetric(origin2, ipType, scope)

		dataSet.Add(decision2)

		after1_2 := getActiveDecisionsMetric(origin1, ipType, scope)
		after2_2 := getActiveDecisionsMetric(origin2, ipType, scope)

		assert.InDelta(t, before1_2, after1_2, 0.001, "origin1 metric should not change")
		assert.InDelta(t, before2_2+1, after2_2, 0.001, "origin2 metric should increment")
	})
}

func TestMetrics_NoOp_DuplicateDecisions(t *testing.T) {
	dataSet := New()

	origin := "test-origin-noop"
	ipType := "ipv4"

	t.Run("Duplicate IP decision is no-op", func(t *testing.T) {
		decision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("10.10.10.10"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		// Add decision first time
		before := getActiveDecisionsMetric(origin, ipType, "ip")
		dataSet.Add(decision)
		afterFirst := getActiveDecisionsMetric(origin, ipType, "ip")
		assert.InDelta(t, float64(len(decision))+before, afterFirst, 0.001, "metric should increment on first add")

		// Add exact same decision again (should be no-op)
		dataSet.Add(decision)
		afterSecond := getActiveDecisionsMetric(origin, ipType, "ip")
		assert.InDelta(t, afterFirst, afterSecond, 0.001, "metric should not change on duplicate add (no-op)")

		// Verify decision still exists and is correct
		ip, err := netip.ParseAddr("10.10.10.10")
		require.NoError(t, err)
		r, foundOrigin, found := dataSet.IPMap.Contains(ip)
		assert.True(t, found, "IP should still exist")
		assert.Equal(t, origin, foundOrigin, "origin should match")
		assert.Equal(t, remediation.Ban, r, "remediation should be ban")
	})

	t.Run("Duplicate range decision is no-op", func(t *testing.T) {
		decision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Range"),
				Value:  ptr.Of("10.0.0.0/8"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		// Add decision first time
		before := getActiveDecisionsMetric(origin, ipType, "range")
		dataSet.Add(decision)
		afterFirst := getActiveDecisionsMetric(origin, ipType, "range")
		assert.InDelta(t, float64(len(decision))+before, afterFirst, 0.001, "metric should increment on first add")

		// Add exact same decision again (should be no-op)
		dataSet.Add(decision)
		afterSecond := getActiveDecisionsMetric(origin, ipType, "range")
		assert.InDelta(t, afterFirst, afterSecond, 0.001, "metric should not change on duplicate add (no-op)")

		// Verify decision still exists
		testIP, err := netip.ParseAddr("10.0.0.1")
		require.NoError(t, err)
		r, foundOrigin := dataSet.RangeSet.Contains(testIP)
		assert.Equal(t, origin, foundOrigin, "origin should match")
		assert.Equal(t, remediation.Ban, r, "remediation should be ban")
	})

	t.Run("Duplicate country decision is no-op", func(t *testing.T) {
		decision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("Country"),
				Value:  ptr.Of("US"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		// Add decision first time
		before := getActiveDecisionsMetric(origin, "", "country")
		dataSet.Add(decision)
		afterFirst := getActiveDecisionsMetric(origin, "", "country")
		assert.InDelta(t, float64(len(decision))+before, afterFirst, 0.001, "metric should increment on first add")

		// Add exact same decision again (should be no-op)
		dataSet.Add(decision)
		afterSecond := getActiveDecisionsMetric(origin, "", "country")
		assert.InDelta(t, afterFirst, afterSecond, 0.001, "metric should not change on duplicate add (no-op)")

		// Verify decision still exists
		r, foundOrigin := dataSet.CNSet.Contains("US")
		assert.Equal(t, origin, foundOrigin, "origin should match")
		assert.Equal(t, remediation.Ban, r, "remediation should be ban")
	})

	t.Run("Same IP different remediation is not no-op", func(t *testing.T) {
		banDecision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.100.1"),
				Type:   ptr.Of("ban"),
				Origin: ptr.Of(origin),
			},
		}

		before := getActiveDecisionsMetric(origin, ipType, "ip")
		dataSet.Add(banDecision)
		afterBan := getActiveDecisionsMetric(origin, ipType, "ip")
		assert.InDelta(t, float64(len(banDecision))+before, afterBan, 0.001, "metric should increment after adding ban")

		// Add same IP with different remediation - should NOT be no-op
		captchaDecision := models.GetDecisionsResponse{
			{
				Scope:  ptr.Of("IP"),
				Value:  ptr.Of("192.168.100.1"),
				Type:   ptr.Of("captcha"),
				Origin: ptr.Of(origin),
			},
		}

		beforeCaptcha := getActiveDecisionsMetric(origin, ipType, "ip")
		dataSet.Add(captchaDecision)
		afterCaptcha := getActiveDecisionsMetric(origin, ipType, "ip")
		assert.InDelta(t, beforeCaptcha+1, afterCaptcha, 0.001, "metric should increment when adding different remediation")
	})
}
