package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	BlockedRequestMetricName      = "crowdsec_haproxy_spoa_bouncer_blocked_requests"
	ProcessedRequestMetricName    = "crowdsec_haproxy_spoa_bouncer_processed_requests"
	ActiveDecisionsMetricName     = "crowdsec_haproxy_spoa_bouncer_active_decisions"
	IPCheckDurationMetricName     = "crowdsec_haproxy_spoa_bouncer_ip_check_duration_seconds"
	CaptchaValidationDurationName = "crowdsec_haproxy_spoa_bouncer_captcha_validation_duration_seconds"
	GeoLookupDurationMetricName   = "crowdsec_haproxy_spoa_bouncer_geo_lookup_duration_seconds"
)

var TotalBlockedRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: BlockedRequestMetricName,
	Help: "Total number of blocked requests",
}, []string{"origin", "ip_type", "remediation"})
var LastBlockedRequestValue map[string]float64 = make(map[string]float64)

var TotalProcessedRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: ProcessedRequestMetricName,
	Help: "Total number of processed requests",
}, []string{"ip_type"})
var LastProcessedRequestValue map[string]float64 = make(map[string]float64)

var TotalActiveDecisions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: ActiveDecisionsMetricName,
	Help: "Total number of active decisions",
}, []string{"origin", "ip_type", "scope"})

// IPCheckDuration tracks the duration of IP/remediation checks
// Labels: lookup_type (ip, range, country)
// Buckets optimized for 0-500ms timeout threshold (10 buckets max)
var IPCheckDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name: IPCheckDurationMetricName,
	Help: "Duration of IP check operations in seconds",
	Buckets: []float64{
		0.001, // 1ms - very fast
		0.01,  // 10ms - fast
		0.05,  // 50ms - normal
		0.1,   // 100ms - getting slower
		0.2,   // 200ms - approaching timeout
		0.3,   // 300ms - close to timeout
		0.4,   // 400ms - very close to timeout
		0.5,   // 500ms - timeout threshold
		1.0,   // 1s - exceeded timeout
		2.0,   // 2s - way over timeout
	},
}, []string{"lookup_type"})

// CaptchaValidationDuration tracks the duration of captcha validation operations
// Buckets optimized for 0-500ms timeout threshold (10 buckets max)
var CaptchaValidationDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
	Name: CaptchaValidationDurationName,
	Help: "Duration of captcha validation operations in seconds",
	Buckets: []float64{
		0.001, // 1ms - very fast
		0.01,  // 10ms - fast
		0.05,  // 50ms - normal
		0.1,   // 100ms - getting slower
		0.2,   // 200ms - approaching timeout
		0.3,   // 300ms - close to timeout
		0.4,   // 400ms - very close to timeout
		0.5,   // 500ms - timeout threshold
		1.0,   // 1s - exceeded timeout
		2.0,   // 2s - way over timeout
	},
})

// GeoLookupDuration tracks the duration of geo database lookups
// Buckets optimized for 0-500ms timeout threshold (10 buckets max)
var GeoLookupDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
	Name: GeoLookupDurationMetricName,
	Help: "Duration of geo database lookup operations in seconds",
	Buckets: []float64{
		0.001, // 1ms - very fast
		0.01,  // 10ms - fast
		0.05,  // 50ms - normal
		0.1,   // 100ms - getting slower
		0.2,   // 200ms - approaching timeout
		0.3,   // 300ms - close to timeout
		0.4,   // 400ms - very close to timeout
		0.5,   // 500ms - timeout threshold
		1.0,   // 1s - exceeded timeout
		2.0,   // 2s - way over timeout
	},
})
