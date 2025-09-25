package appsec

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api/messages"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppSec_ValidateRequest_Allow(t *testing.T) {
	// Create a test server that returns 200 (allow)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "192.168.1.1", r.Header.Get("X-Crowdsec-Appsec-Ip"))
		assert.Equal(t, "/test", r.Header.Get("X-Crowdsec-Appsec-Uri"))
		assert.Equal(t, "example.com", r.Header.Get("X-Crowdsec-Appsec-Host"))
		assert.Equal(t, "GET", r.Header.Get("X-Crowdsec-Appsec-Verb"))
		assert.Equal(t, "test-api-key", r.Header.Get("X-Crowdsec-Appsec-Api-Key"))
		assert.Equal(t, "Mozilla/5.0", r.Header.Get("X-Crowdsec-Appsec-User-Agent"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	appSec := &AppSec{}
	logger := logrus.NewEntry(logrus.New())
	err := appSec.Init(logger, context.Background(), server.URL, "test-api-key")
	require.NoError(t, err)

	req := &messages.AppSecRequest{
		Host:      "example.com",
		Method:    "GET",
		URL:       "/test",
		RemoteIP:  "192.168.1.1",
		UserAgent: "Mozilla/5.0",
		Headers:   make(http.Header),
		Body:      nil,
	}

	result, err := appSec.ValidateRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, remediation.Allow, result)
}

func TestAppSec_ValidateRequest_Ban(t *testing.T) {
	// Create a test server that returns 403 (ban)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	appSec := &AppSec{}
	logger := logrus.NewEntry(logrus.New())
	err := appSec.Init(logger, context.Background(), server.URL, "test-api-key")
	require.NoError(t, err)

	req := &messages.AppSecRequest{
		Host:      "example.com",
		Method:    "GET",
		URL:       "/test",
		RemoteIP:  "192.168.1.1",
		UserAgent: "Mozilla/5.0",
		Headers:   make(http.Header),
		Body:      nil,
	}

	result, err := appSec.ValidateRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, remediation.Ban, result)
}

func TestAppSec_ValidateRequest_NoURL(t *testing.T) {
	appSec := &AppSec{}
	logger := logrus.NewEntry(logrus.New())
	err := appSec.Init(logger, context.Background(), "", "test-api-key")
	require.NoError(t, err)

	req := &messages.AppSecRequest{
		Host:      "example.com",
		Method:    "GET",
		URL:       "/test",
		RemoteIP:  "192.168.1.1",
		UserAgent: "Mozilla/5.0",
		Headers:   make(http.Header),
		Body:      nil,
	}

	result, err := appSec.ValidateRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, remediation.Allow, result)
}

func TestAppSec_ValidateRequest_POST(t *testing.T) {
	// Create a test server that returns 200 (allow)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		// Read the body to verify it was sent correctly
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, "test-body", string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	appSec := &AppSec{}
	logger := logrus.NewEntry(logrus.New())
	err := appSec.Init(logger, context.Background(), server.URL, "test-api-key")
	require.NoError(t, err)

	req := &messages.AppSecRequest{
		Host:      "example.com",
		Method:    "POST",
		URL:       "/test",
		RemoteIP:  "192.168.1.1",
		UserAgent: "Mozilla/5.0",
		Headers:   make(http.Header),
		Body:      []byte("test-body"),
	}

	result, err := appSec.ValidateRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, remediation.Allow, result)
}
