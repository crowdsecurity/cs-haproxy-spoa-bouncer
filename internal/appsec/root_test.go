package appsec

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestAppSec returns an AppSec with a client pointed at the given URL.
func newTestAppSec(url, apiKey string) *AppSec {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))
	a.Client = &AppSecClient{
		HTTPClient: &http.Client{},
		APIKey:     apiKey,
		URL:        url,
		logger:     a.logger,
	}
	return a
}

// ---------- parseResponse unit tests ----------

func TestProcessAppSecResponse_Allow(t *testing.T) {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))

	rem, cd, err := a.processAppSecResponse(http.StatusOK, nil)

	require.NoError(t, err)
	assert.Equal(t, remediation.Allow, rem)
	assert.Nil(t, cd)
}

func TestProcessAppSecResponse_BanPlain403(t *testing.T) {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))

	body, _ := json.Marshal(map[string]interface{}{"action": "ban", "http_status": 403})
	rem, cd, err := a.processAppSecResponse(http.StatusForbidden, body)

	require.NoError(t, err)
	assert.Equal(t, remediation.Ban, rem)
	assert.Nil(t, cd)
}

func TestProcessAppSecResponse_BanEmptyBody(t *testing.T) {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))

	rem, cd, err := a.processAppSecResponse(http.StatusForbidden, nil)

	require.NoError(t, err)
	assert.Equal(t, remediation.Ban, rem)
	assert.Nil(t, cd)
}

func TestProcessAppSecResponse_BanInvalidJSON(t *testing.T) {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))

	rem, cd, err := a.processAppSecResponse(http.StatusForbidden, []byte("not json"))

	require.NoError(t, err) // invalid JSON is treated as ban, not an error
	assert.Equal(t, remediation.Ban, rem)
	assert.Nil(t, cd)
}

func TestProcessAppSecResponse_ChallengeMinimal(t *testing.T) {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))

	body, _ := json.Marshal(map[string]interface{}{
		"action":             "challenge",
		"http_status":        200,
		"user_body_content":  "<html>challenge</html>",
		"user_headers":       map[string][]string{"Content-Type": {"text/html"}},
		"user_cookies":       []string{},
	})

	rem, cd, err := a.processAppSecResponse(http.StatusForbidden, body)

	require.NoError(t, err)
	assert.Equal(t, remediation.Challenge, rem)
	require.NotNil(t, cd)
	assert.Equal(t, 200, cd.StatusCode)
	assert.Equal(t, "<html>challenge</html>", cd.Body)
	assert.Equal(t, "text/html", cd.ContentType)
	assert.Empty(t, cd.Cookies)
}

func TestProcessAppSecResponse_ChallengeWithAllHeaders(t *testing.T) {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))

	body, _ := json.Marshal(map[string]interface{}{
		"action":            "challenge",
		"http_status":       200,
		"user_body_content": "<html>challenge</html>",
		"user_headers": map[string][]string{
			"Content-Type":              {"text/html; charset=utf-8"},
			"Content-Security-Policy":   {"default-src 'self'"},
			"Cache-Control":             {"no-store, no-cache"},
		},
		"user_cookies": []string{"__crowdsec_challenge=abc123; HttpOnly; SameSite=Lax"},
	})

	rem, cd, err := a.processAppSecResponse(http.StatusForbidden, body)

	require.NoError(t, err)
	assert.Equal(t, remediation.Challenge, rem)
	require.NotNil(t, cd)
	assert.Equal(t, "text/html; charset=utf-8", cd.ContentType)
	assert.Equal(t, "default-src 'self'", cd.CSP)
	assert.Equal(t, "no-store, no-cache", cd.CacheControl)
	assert.Equal(t, []string{"__crowdsec_challenge=abc123; HttpOnly; SameSite=Lax"}, cd.Cookies)
}

func TestProcessAppSecResponse_Unauthorized(t *testing.T) {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))

	rem, cd, err := a.processAppSecResponse(http.StatusUnauthorized, nil)

	require.Error(t, err)
	assert.Equal(t, remediation.Allow, rem)
	assert.Nil(t, cd)
}

func TestProcessAppSecResponse_InternalServerError(t *testing.T) {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))

	rem, cd, err := a.processAppSecResponse(http.StatusInternalServerError, nil)

	require.Error(t, err)
	assert.Equal(t, remediation.Allow, rem)
	assert.Nil(t, cd)
}

func TestProcessAppSecResponse_UnknownStatus(t *testing.T) {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))

	rem, cd, err := a.processAppSecResponse(418, nil)

	require.Error(t, err)
	assert.Equal(t, remediation.Allow, rem)
	assert.Nil(t, cd)
}

// ---------- ValidateRequest integration tests (httptest server) ----------

func TestValidateRequest_Allow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newTestAppSec(srv.URL, "test-key")
	rem, cd, err := a.ValidateRequest(context.Background(), &AppSecRequest{
		Host: "example.com", Method: "GET", URL: "/", RemoteIP: "1.2.3.4",
	})

	require.NoError(t, err)
	assert.Equal(t, remediation.Allow, rem)
	assert.Nil(t, cd)
}

func TestValidateRequest_Ban(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"action": "ban", "http_status": 403})
	}))
	defer srv.Close()

	a := newTestAppSec(srv.URL, "test-key")
	rem, cd, err := a.ValidateRequest(context.Background(), &AppSecRequest{
		Host: "example.com", Method: "GET", URL: "/?id=1 OR 1=1", RemoteIP: "1.2.3.4",
	})

	require.NoError(t, err)
	assert.Equal(t, remediation.Ban, rem)
	assert.Nil(t, cd)
}

func TestValidateRequest_Challenge(t *testing.T) {
	const challengeHTML = "<html><title>CrowdSec Challenge</title></html>"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"action":            "challenge",
			"http_status":       200,
			"user_body_content": challengeHTML,
			"user_headers": map[string][]string{
				"Content-Type":            {"text/html"},
				"Content-Security-Policy": {"default-src 'self'"},
				"Cache-Control":           {"no-store"},
			},
			"user_cookies": []string{"__crowdsec_challenge=xyz; HttpOnly"},
		})
	}))
	defer srv.Close()

	a := newTestAppSec(srv.URL, "test-key")
	rem, cd, err := a.ValidateRequest(context.Background(), &AppSecRequest{
		Host: "example.com", Method: "GET", URL: "/challenge", RemoteIP: "1.2.3.4",
	})

	require.NoError(t, err)
	assert.Equal(t, remediation.Challenge, rem)
	require.NotNil(t, cd)
	assert.Equal(t, 200, cd.StatusCode)
	assert.Equal(t, challengeHTML, cd.Body)
	assert.Equal(t, "text/html", cd.ContentType)
	assert.Equal(t, "default-src 'self'", cd.CSP)
	assert.Equal(t, "no-store", cd.CacheControl)
	assert.Equal(t, []string{"__crowdsec_challenge=xyz; HttpOnly"}, cd.Cookies)
}

func TestValidateRequest_NotConfigured(t *testing.T) {
	a := &AppSec{}
	a.InitLogger(log.NewEntry(log.New()))
	// No Client set → IsValid() == false

	rem, cd, err := a.ValidateRequest(context.Background(), &AppSecRequest{
		Host: "example.com", Method: "GET", URL: "/", RemoteIP: "1.2.3.4",
	})

	require.NoError(t, err)
	assert.Equal(t, remediation.Allow, rem)
	assert.Nil(t, cd)
}

func TestValidateRequest_SendsRequiredHeaders(t *testing.T) {
	var capturedReq *http.Request

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newTestAppSec(srv.URL, "secret-api-key")
	_, _, _ = a.ValidateRequest(context.Background(), &AppSecRequest{
		Host:      "myhost.com",
		Method:    "POST",
		URL:       "/login",
		RemoteIP:  "10.0.0.1",
		UserAgent: "Mozilla/5.0",
		Version:   "1.1",
	})

	require.NotNil(t, capturedReq)
	assert.Equal(t, "10.0.0.1", capturedReq.Header.Get("X-Crowdsec-Appsec-Ip"))
	assert.Equal(t, "/login", capturedReq.Header.Get("X-Crowdsec-Appsec-Uri"))
	assert.Equal(t, "myhost.com", capturedReq.Header.Get("X-Crowdsec-Appsec-Host"))
	assert.Equal(t, "POST", capturedReq.Header.Get("X-Crowdsec-Appsec-Verb"))
	assert.Equal(t, "secret-api-key", capturedReq.Header.Get("X-Crowdsec-Appsec-Api-Key"))
	assert.Equal(t, "Mozilla/5.0", capturedReq.Header.Get("X-Crowdsec-Appsec-User-Agent"))
	assert.Equal(t, "11", capturedReq.Header.Get("X-Crowdsec-Appsec-Http-Version"))
}

func TestValidateRequest_PostWithBody(t *testing.T) {
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newTestAppSec(srv.URL, "key")
	payload := []byte("t=token&n=nonce&f=fingerprint")
	_, _, _ = a.ValidateRequest(context.Background(), &AppSecRequest{
		Host: "example.com", Method: "POST", URL: "/submit", RemoteIP: "1.2.3.4",
		Body: payload,
	})

	assert.Equal(t, payload, receivedBody)
}
