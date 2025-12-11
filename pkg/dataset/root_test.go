package dataset

import (
	"net/netip"
	"testing"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// toCheck is a struct to check the result of the addition or deletion of a decision
type toCheck struct {
	Value  string // IP, Country
	Scope  string // IP, Country
	Origin string
	Type   remediation.Remediation // remediation type
}

func TestDataSet(t *testing.T) {
	dataSet := New()
	t.Run("Test Init", func(t *testing.T) {
		// Test new returns the types we expect
		assert.NotNil(t, dataSet)
		assert.IsType(t, &CNSet{}, dataSet.CNSet)
		assert.IsType(t, &IPMap{}, dataSet.IPMap)
		assert.IsType(t, &BartRangeSet{}, dataSet.RangeSet)
		assert.NotNil(t, dataSet.CNSet)
		assert.NotNil(t, dataSet.IPMap)
		assert.NotNil(t, dataSet.RangeSet)
	})
	tests := []struct {
		name     string
		toAdd    models.GetDecisionsResponse
		toDelete models.GetDecisionsResponse
		toCheck  *toCheck
	}{
		{
			name: "Test IP Add",
			toAdd: models.GetDecisionsResponse{
				{
					Scope:  ptr.Of("IP"),
					Value:  ptr.Of("192.168.1.1"),
					Type:   ptr.Of("ban"),
					Origin: ptr.Of("crowdsec"),
					ID:     1,
				},
			},
			toCheck: &toCheck{
				Value:  "192.168.1.1",
				Scope:  "IP",
				Origin: "crowdsec",
				Type:   remediation.Ban,
			},
		},
		{
			name: "Test IP Delete",
			toDelete: models.GetDecisionsResponse{
				{
					Scope:  ptr.Of("IP"),
					Value:  ptr.Of("192.168.1.1"),
					Type:   ptr.Of("ban"),
					Origin: ptr.Of("crowdsec"),
					ID:     1,
				},
			},
			toCheck: &toCheck{
				Value: "192.168.1.1",
				Scope: "IP",
				Type:  remediation.Allow,
			},
		},
		{
			name: "Test Range Add",
			toAdd: models.GetDecisionsResponse{
				{
					Scope:  ptr.Of("Range"),
					Value:  ptr.Of("192.168.1.0/24"),
					Type:   ptr.Of("ban"),
					Origin: ptr.Of("crowdsec"),
					ID:     2,
				},
			},
			toCheck: &toCheck{
				Value:  "192.168.1.24",
				Scope:  "IP",
				Origin: "crowdsec",
				Type:   remediation.Ban,
			},
		},
		{
			name: "Test Range Delete",
			toDelete: models.GetDecisionsResponse{
				{
					Scope:  ptr.Of("Range"),
					Value:  ptr.Of("192.168.1.0/24"),
					Type:   ptr.Of("ban"),
					Origin: ptr.Of("crowdsec"),
					ID:     2,
				},
			},
			toCheck: &toCheck{
				Value: "192.168.1.1",
				Scope: "IP",
				Type:  remediation.Allow,
			},
		},
		{
			name: "Test Country Add",
			toAdd: models.GetDecisionsResponse{
				{
					Scope:  ptr.Of("Country"),
					Value:  ptr.Of("FR"),
					Type:   ptr.Of("ban"),
					Origin: ptr.Of("crowdsec"),
					ID:     3,
				},
			},
			toCheck: &toCheck{
				Value:  "FR",
				Scope:  "Country",
				Origin: "crowdsec",
				Type:   remediation.Ban,
			},
		},
		{
			name: "Test Country Delete",
			toDelete: models.GetDecisionsResponse{
				{
					Scope:  ptr.Of("Country"),
					Value:  ptr.Of("FR"),
					Type:   ptr.Of("ban"),
					Origin: ptr.Of("crowdsec"),
					ID:     3,
				},
			},
			toCheck: &toCheck{
				Value: "FR",
				Scope: "Country",
				Type:  remediation.Allow,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.toAdd) > 0 {
				dataSet.Add(tt.toAdd)
			}
			if len(tt.toDelete) > 0 {
				dataSet.Remove(tt.toDelete)
			}
			if tt.toCheck == nil {
				t.Fatalf("toCheck is nil")
			}
			var r remediation.Remediation
			var err error
			var origin string
			switch tt.toCheck.Scope {
			case "IP":
				addr, parseErr := netip.ParseAddr(tt.toCheck.Value)
				require.NoError(t, parseErr)
				r, origin, err = dataSet.CheckIP(addr)
			case "Country":
				r, origin = dataSet.CheckCN(tt.toCheck.Value)
			default:
				t.Fatalf("unknown scope %s", tt.toCheck.Scope)
			}
			require.NoError(t, err)
			assert.True(t, remediation.IsEqual(r, tt.toCheck.Type), "remediation should match: got %s, expected %s", r.String(), tt.toCheck.Type.String())
			assert.Equal(t, origin, tt.toCheck.Origin)
		})
	}

}
