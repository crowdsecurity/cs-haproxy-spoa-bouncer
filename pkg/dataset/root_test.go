package dataset

import (
	"testing"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// toCheck is a struct to check the result of the addition or deletion of a decision
type toCheck struct {
	Value string // IP, Country
	Scope string // IP, Country
	Type  remediation.Remediation
}

func TestDataSet(t *testing.T) {
	dataSet := New()
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
					Scope: ptr.Of("IP"),
					Value: ptr.Of("192.168.1.1"),
					Type:  ptr.Of("ban"),
					ID:    1,
				},
			},
			toCheck: &toCheck{
				Value: "192.168.1.1",
				Scope: "IP",
				Type:  remediation.Ban,
			},
		},
		{
			name: "Test IP Delete",
			toDelete: models.GetDecisionsResponse{
				{
					Scope: ptr.Of("IP"),
					Value: ptr.Of("192.168.1.1"),
					Type:  ptr.Of("ban"),
					ID:    1,
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
					Scope: ptr.Of("Range"),
					Value: ptr.Of("192.168.1.0/24"),
					Type:  ptr.Of("ban"),
					ID:    2,
				},
			},
			toCheck: &toCheck{
				Value: "192.168.1.24",
				Scope: "IP",
				Type:  remediation.Ban,
			},
		},
		{
			name: "Test Range Delete",
			toDelete: models.GetDecisionsResponse{
				{
					Scope: ptr.Of("Range"),
					Value: ptr.Of("192.168.1.0/24"),
					Type:  ptr.Of("ban"),
					ID:    2,
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
					Scope: ptr.Of("Country"),
					Value: ptr.Of("FR"),
					Type:  ptr.Of("ban"),
					ID:    3,
				},
			},
			toCheck: &toCheck{
				Value: "FR",
				Scope: "Country",
				Type:  remediation.Ban,
			},
		},
		{
			name: "Test Country Delete",
			toDelete: models.GetDecisionsResponse{
				{
					Scope: ptr.Of("Country"),
					Value: ptr.Of("FR"),
					Type:  ptr.Of("ban"),
					ID:    3,
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
				if tt.toCheck == nil {
					t.Fatalf("toCheck is nil")
				}
				var r remediation.Remediation
				var err error
				switch tt.toCheck.Scope {
				case "IP":
					r, err = dataSet.CheckIP(tt.toCheck.Value)
				case "Country":
					r = dataSet.CheckCN(tt.toCheck.Value)
				default:
					t.Fatalf("unknown scope %s", tt.toCheck.Scope)
				}
				require.NoError(t, err)
				assert.Equal(t, r, tt.toCheck.Type)
			}
			if len(tt.toDelete) > 0 {
				dataSet.Remove(tt.toDelete)
			}
		})
	}

}
