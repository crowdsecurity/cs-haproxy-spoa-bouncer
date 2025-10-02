package appsec

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api/messages"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// AppSecClient handles HTTP communication with the AppSec engine
type AppSecClient struct {
	HTTPClient *http.Client
	APIKey     string
	URL        string
	logger     *log.Entry
}

// AppSec represents the AppSec configuration for a host
type AppSec struct {
	AlwaysSend bool   `yaml:"always_send"`
	URL        string `yaml:"url,omitempty"`     // Host-specific AppSec URL (overrides global)
	APIKey     string `yaml:"api_key,omitempty"` // Host-specific API key (overrides global)
	Client     *AppSecClient
	logger     *log.Entry `yaml:"-"`
}

func (a *AppSec) Init(logger *log.Entry, ctx context.Context, globalURL, globalAPIKey string) error {
	a.InitLogger(logger)

	// Use host-specific config if provided, otherwise fall back to global
	url := a.URL
	if url == "" {
		url = globalURL
	}

	apiKey := a.APIKey
	if apiKey == "" {
		apiKey = globalAPIKey
	}

	// Create AppSec client
	a.Client = &AppSecClient{
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		APIKey: apiKey,
		URL:    url,
		logger: a.logger,
	}

	a.logger.WithFields(log.Fields{
		"url":         url,
		"api_key_set": apiKey != "",
	}).Debug("AppSec client initialized")

	return nil
}

func (a *AppSec) InitLogger(logger *log.Entry) {
	a.logger = logger.WithField("type", "appsec")
}

// ValidateRequest sends the HTTP request to the AppSec engine and returns the remediation
func (a *AppSec) ValidateRequest(ctx context.Context, req *messages.AppSecRequest) (remediation.Remediation, error) {
	if a.Client == nil {
		a.logger.Debug("AppSec client not initialized, allowing request")
		return remediation.Allow, nil
	}

	if a.Client.URL == "" {
		a.logger.Debug("AppSec URL not configured, allowing request")
		return remediation.Allow, nil
	}

	// Create HTTP request to AppSec engine
	httpReq, err := a.createAppSecRequest(req)
	if err != nil {
		a.logger.Errorf("Failed to create AppSec request: %v", err)
		return remediation.Allow, err
	}

	// Send request to AppSec engine
	resp, err := a.Client.HTTPClient.Do(httpReq.WithContext(ctx))
	if err != nil {
		a.logger.Errorf("Failed to send request to AppSec engine: %v", err)
		return remediation.Allow, err
	}
	defer resp.Body.Close()

	// Process response based on HTTP status code
	rem, err := a.processAppSecResponse(resp)
	if rem > remediation.Allow {
		addr, err2 := netip.ParseAddr(req.RemoteIP)
		if err2 != nil || !addr.IsValid() {
			a.logger.Errorf("%s is not valid: %v\n", req.RemoteIP, err)
			return rem, err
		}
		var iptype string
		if addr.Is4() {
			iptype = "ipv4"
		} else {
			iptype = "ipv6"
		}

		metrics.TotalBlockedRequests.With(prometheus.Labels{"ip_type": iptype, "origin": "appsec", "remediation": rem.String()}).Inc()
	}

	return rem, err
}

func (a *AppSec) createAppSecRequest(req *messages.AppSecRequest) (*http.Request, error) {
	var httpReq *http.Request
	var err error

	// Debug logging to see what we're receiving
	a.logger.WithFields(log.Fields{
		"host":       req.Host,
		"method":     req.Method,
		"url":        req.URL,
		"remote_ip":  req.RemoteIP,
		"user_agent": req.UserAgent,
	}).Debug("Creating AppSec request")

	// Determine HTTP method based on whether there's a body
	if len(req.Body) > 0 {
		httpReq, err = http.NewRequest(http.MethodPost, a.Client.URL, bytes.NewReader(req.Body))
	} else {
		httpReq, err = http.NewRequest(http.MethodGet, a.Client.URL, http.NoBody)
	}

	if err != nil {
		return nil, err
	}

	// Copy original headers first
	if req.Headers != nil {
		for key, values := range req.Headers {
			for _, value := range values {
				httpReq.Header.Add(key, value)
			}
		}
	}

	// Now override with our trusted CrowdSec headers
	httpReq.Header.Set("X-Crowdsec-Appsec-Ip", req.RemoteIP)
	httpReq.Header.Set("X-Crowdsec-Appsec-Uri", req.URL)
	httpReq.Header.Set("X-Crowdsec-Appsec-Host", req.Host)
	httpReq.Header.Set("X-Crowdsec-Appsec-Verb", req.Method)

	// Ensure we have a valid API key
	if a.Client.APIKey == "" {
		a.logger.Error("AppSec API key is empty")
		return nil, fmt.Errorf("AppSec API key is not configured")
	}

	httpReq.Header.Set("X-Crowdsec-Appsec-Api-Key", a.Client.APIKey)
	httpReq.Header.Set("X-Crowdsec-Appsec-User-Agent", req.UserAgent)

	// Set HTTP version from the request (set by HAProxy SPOE)
	httpVersion := "11" // Default to HTTP/1.1
	if req.Version != "" {
		// Convert version format from HAProxy (e.g., "1.1", "2.0") to our format (e.g., "11", "20")
		switch req.Version {
		case "1.0":
			httpVersion = "10"
		case "1.1":
			httpVersion = "11"
		case "2.0":
			httpVersion = "20"
		case "3.0":
			httpVersion = "30"
		default:
			// For any other version, just strip the dots
			httpVersion = strings.ReplaceAll(req.Version, ".", "")
		}
	}
	httpReq.Header.Set("X-Crowdsec-Appsec-Http-Version", httpVersion)

	return httpReq, nil
}

func (a *AppSec) processAppSecResponse(resp *http.Response) (remediation.Remediation, error) {
	switch resp.StatusCode {
	case http.StatusOK:
		// Request allowed
		return remediation.Allow, nil

	case http.StatusForbidden:
		// Request blocked - return ban remediation
		return remediation.Ban, nil

	case http.StatusUnauthorized:
		// Authentication failed
		a.logger.Error("AppSec authentication failed - check API key")
		return remediation.Allow, fmt.Errorf("AppSec authentication failed")

	case http.StatusInternalServerError:
		// AppSec engine error
		a.logger.Error("AppSec engine error")
		return remediation.Allow, fmt.Errorf("AppSec engine error")

	default:
		a.logger.Warnf("Unexpected AppSec response code: %d", resp.StatusCode)
		return remediation.Allow, fmt.Errorf("unexpected AppSec response code: %d", resp.StatusCode)
	}
}
