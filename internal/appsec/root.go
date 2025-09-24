package appsec

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api/messages"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
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
	return a.processAppSecResponse(resp)
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
		httpReq, err = http.NewRequest("POST", a.Client.URL, bytes.NewReader(req.Body))
	} else {
		httpReq, err = http.NewRequest("GET", a.Client.URL, nil)
	}

	if err != nil {
		return nil, err
	}

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

	// Set HTTP version (default to 1.1 if not specified)
	httpVersion := "11"
	if req.Headers != nil {
		if version := req.Headers.Get("HTTP-Version"); version != "" {
			httpVersion = version
		}
	}
	httpReq.Header.Set("X-Crowdsec-Appsec-Http-Version", httpVersion)

	// Copy original headers
	if req.Headers != nil {
		for key, values := range req.Headers {
			// Skip headers that might conflict with our AppSec headers
			if !strings.HasPrefix(strings.ToLower(key), "x-crowdsec-appsec-") {
				for _, value := range values {
					httpReq.Header.Add(key, value)
				}
			}
		}
	}

	return httpReq, nil
}

func (a *AppSec) processAppSecResponse(resp *http.Response) (remediation.Remediation, error) {
	switch resp.StatusCode {
	case 200:
		// Request allowed
		return remediation.Allow, nil

	case 403:
		// Request blocked - return ban remediation
		return remediation.Ban, nil

	case 401:
		// Authentication failed
		a.logger.Error("AppSec authentication failed - check API key")
		return remediation.Allow, fmt.Errorf("AppSec authentication failed")

	case 500:
		// AppSec engine error
		a.logger.Error("AppSec engine error")
		return remediation.Allow, fmt.Errorf("AppSec engine error")

	default:
		a.logger.Warnf("Unexpected AppSec response code: %d", resp.StatusCode)
		return remediation.Allow, fmt.Errorf("unexpected AppSec response code: %d", resp.StatusCode)
	}
}
