package cmd

import (
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
)

func getLabelValue(labels []*io_prometheus_client.LabelPair, key string) string {

	for _, label := range labels {
		if label.GetName() == key {
			return label.GetValue()
		}
	}

	return ""
}

func metricsUpdater(met *models.RemediationComponentsMetrics, updateInterval time.Duration) {
	promMetrics, err := prometheus.DefaultGatherer.Gather()

	if err != nil {
		log.Errorf("failed to gather prometheus metrics: %s", err)
		return
	}

	met.Metrics = append(met.Metrics, &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   ptr.Of(time.Now().Unix()),
			WindowSizeSeconds: ptr.Of(int64(updateInterval.Seconds())),
		},
	})

	for _, metricFamily := range promMetrics {
		for _, metric := range metricFamily.GetMetric() {
			switch metricFamily.GetName() {
			case metrics.ActiveBannedIPsMetricName:
				labels := metric.GetLabel()
				value := metric.GetGauge().GetValue()
				origin := getLabelValue(labels, "origin")
				ipType := getLabelValue(labels, "type")
				log.Debugf("Sending active decisions for %s %s | current value: %f", origin, ipType, value)
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("active_decisions"),
					Value: ptr.Of(value),
					Labels: map[string]string{
						"origin":  origin,
						"ip_type": ipType,
					},
					Unit: ptr.Of("ip"),
				})
			case metrics.BlockedRequestMetricName:
				labels := metric.GetLabel()
				value := metric.GetGauge().GetValue()
				origin := getLabelValue(labels, "origin")
				ipType := getLabelValue(labels, "ip_type")
				remediation := getLabelValue(labels, "remediation")
				key := origin + ipType + remediation
				log.Debugf("Sending blocked requests for %s %s %s %f | current value: %f | previous value: %f\n", origin, ipType, remediation, value-metrics.LastBlockedRequestValue[key], value, metrics.LastBlockedRequestValue[key])
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("dropped"),
					Value: ptr.Of(value - metrics.LastBlockedRequestValue[key]),
					Labels: map[string]string{
						"origin":  origin,
						"ip_type": ipType,
					},
					Unit: ptr.Of("byte"),
				})
				metrics.LastBlockedRequestValue[key] = value
			case metrics.ProcessedRequestMetricName:
				labels := metric.GetLabel()
				value := metric.GetGauge().GetValue()
				origin := getLabelValue(labels, "origin")
				ipType := getLabelValue(labels, "ip_type")
				key := origin + ipType
				log.Debugf("Sending processed requests for %s %s %f | current value: %f | previous value: %f\n", origin, ipType, value-metrics.LastProcessedRequestValue[key], value, metrics.LastProcessedRequestValue[key])
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("dropped"),
					Value: ptr.Of(value - metrics.LastProcessedRequestValue[key]),
					Labels: map[string]string{
						"origin":  origin,
						"ip_type": ipType,
					},
					Unit: ptr.Of("packet"),
				})
				metrics.LastProcessedRequestValue[key] = value
			}
		}
	}
}
