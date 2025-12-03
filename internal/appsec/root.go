package appsec

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

// AppSecRequest represents the HTTP request data to be validated by AppSec
type AppSecRequest struct {
	Host      string
	Method    string
	URL       string
	RemoteIP  string
	UserAgent string
	Version   string
	Headers   http.Header
	Body      []byte
}

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

func (a *AppSec) Init(logger *log.Entry) error {
	a.InitLogger(logger)

	// Use only host-specific config (no global fallback - global AppSec is handled at SPOA level)
	url := a.URL
	apiKey := a.APIKey

	// Only create client if URL is configured
	if url != "" {
		// Configure transport with keep-alive enabled and optimized connection pooling
		transport := &http.Transport{
			MaxIdleConns:        100,              // Total idle connections across all hosts
			MaxIdleConnsPerHost: 10,               // Idle connections per host (default is 2)
			IdleConnTimeout:     90 * time.Second, // How long idle connections are kept
			DisableKeepAlives:   false,            // Enable keep-alive (default)
		}

		a.Client = &AppSecClient{
			HTTPClient: &http.Client{
				// No timeout here - rely on context timeout for request-level control
				Transport: transport,
			},
			APIKey: apiKey,
			URL:    url,
			logger: a.logger,
		}

		a.logger.WithFields(log.Fields{
			"url":         url,
			"api_key_set": apiKey != "",
		}).Debug("AppSec client initialized")
	} else {
		a.logger.Debug("AppSec override not configured for host; AppSec validation will default to global (if set)")
	}

	return nil
}

func (a *AppSec) IsValid() bool {
	return a.Client != nil && a.Client.URL != ""
}

func (a *AppSec) InitLogger(logger *log.Entry) {
	a.logger = logger.WithField("type", "appsec")
}

// ValidateRequest sends the HTTP request to the AppSec engine and returns the remediation
func (a *AppSec) ValidateRequest(ctx context.Context, req *AppSecRequest) (remediation.Remediation, error) {
	// Use IsValid() which checks both Client and URL
	if !a.IsValid() {
		a.logger.Debug("AppSec not configured, allowing request")
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
	// resp is guaranteed to be non-nil when err is nil (per http.Client.Do contract)
	defer resp.Body.Close()

	// Discard response body for proper connection reuse
	// This allows the connection to be reused via keep-alive
	_, _ = io.Copy(io.Discard, resp.Body)

	// Process response based on HTTP status code
	return a.processAppSecResponse(resp)
}

func (a *AppSec) createAppSecRequest(req *AppSecRequest) (*http.Request, error) {
	// Ensure we have a valid API key first (fail fast before processing headers)
	if a.Client.APIKey == "" {
		a.logger.Error("AppSec API key is empty")
		return nil, fmt.Errorf("appsec API key is not configured")
	}

	var httpReq *http.Request
	var err error

	// AppSec API only supports GET or POST methods
	// POST is used only when there's a body, otherwise GET
	if len(req.Body) > 0 {
		httpReq, err = http.NewRequest(http.MethodPost, a.Client.URL, bytes.NewReader(req.Body))
	} else {
		httpReq, err = http.NewRequest(http.MethodGet, a.Client.URL, http.NoBody)
	}

	if err != nil {
		return nil, err
	}

	// Copy original headers
	if req.Headers != nil {
		httpReq.Header = maps.Clone(req.Headers)
	}

	// Now override with our trusted CrowdSec headers
	httpReq.Header.Set("X-Crowdsec-Appsec-Ip", req.RemoteIP)
	httpReq.Header.Set("X-Crowdsec-Appsec-Uri", req.URL)
	httpReq.Header.Set("X-Crowdsec-Appsec-Host", req.Host)
	httpReq.Header.Set("X-Crowdsec-Appsec-Verb", req.Method)

	httpReq.Header.Set("X-Crowdsec-Appsec-Api-Key", a.Client.APIKey)
	httpReq.Header.Set("X-Crowdsec-Appsec-User-Agent", req.UserAgent)

	// Debug logging to see what we're actually sending (log after all headers are set)
	a.logger.WithFields(log.Fields{
		"host":       req.Host,
		"method":     req.Method,
		"url":        req.URL,
		"remote_ip":  req.RemoteIP,
		"user_agent": req.UserAgent,
	}).Debug("Created AppSec request with headers")

	// Set HTTP version from the request (set by HAProxy SPOE)
	// Convert version format from HAProxy (e.g., "1.1", "2.0") to our format (e.g., "11", "20")
	httpVersion := "11" // Default to HTTP/1.1
	if req.Version != "" {
		// Use explicit mapping for known versions to handle edge cases correctly
		switch req.Version {
		case "1.0":
			httpVersion = "10"
		case "1.1":
			httpVersion = "11"
		case "2.0", "2":
			httpVersion = "20"
		default:
			// For unknown formats, strip dots
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
