package spoa

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAppSecHandler returns an http.Handler that responds with the given JSON body
// and status code to simulate the AppSec engine's wire format.
func mockAppSecHandler(statusCode int, payload interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(payload)
	})
}

func newChallengeServerForTest(t *testing.T, appSecHandler http.Handler) (*ChallengeServer, *httptest.Server) {
	t.Helper()
	appSecSrv := httptest.NewServer(appSecHandler)
	t.Cleanup(appSecSrv.Close)

	a := &appsec.AppSec{}
	a.InitLogger(log.NewEntry(log.New()))
	a.Client = &appsec.AppSecClient{
		HTTPClient: &http.Client{},
		APIKey:     "test-api-key",
		URL:        appSecSrv.URL,
		// logger exposed through the embedded unexported field; set via Init below
	}

	cs := newChallengeServer(a, "unused-addr", log.WithField("test", t.Name()))
	return cs, appSecSrv
}

// roundtrip sends req to the ChallengeServer and returns the recorded response.
func roundtrip(cs *ChallengeServer, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	cs.ServeHTTP(rr, req)
	return rr
}

// ---------- tests ----------

func TestChallengeServer_ServesChallengePage(t *testing.T) {
	const challengeHTML = "<html><title>CrowdSec Challenge</title></html>"

	cs, _ := newChallengeServerForTest(t, mockAppSecHandler(http.StatusForbidden, map[string]interface{}{
		"action":            "challenge",
		"http_status":       200,
		"user_body_content": challengeHTML,
		"user_headers": map[string][]string{
			"Content-Type":            {"text/html"},
			"Content-Security-Policy": {"default-src 'self'"},
			"Cache-Control":           {"no-store, no-cache"},
		},
		"user_cookies": []string{},
	}))

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.Header.Set(ChallengeRealIPHeader, "1.2.3.4")
	rr := roundtrip(cs, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, challengeHTML, rr.Body.String())
	assert.Equal(t, "text/html", rr.Header().Get("Content-Type"))
	assert.Equal(t, "default-src 'self'", rr.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "no-store, no-cache", rr.Header().Get("Cache-Control"))
}

func TestChallengeServer_ForwardsCookies(t *testing.T) {
	cs, _ := newChallengeServerForTest(t, mockAppSecHandler(http.StatusForbidden, map[string]interface{}{
		"action":            "challenge",
		"http_status":       200,
		"user_body_content": `{"status":"ok"}`,
		"user_headers":      map[string][]string{"Content-Type": {"application/json"}},
		"user_cookies":      []string{"__crowdsec_challenge=abc123; HttpOnly; Path=/; SameSite=Lax"},
	}))

	req := httptest.NewRequest(http.MethodPost, "/crowdsec-internal/challenge/submit", strings.NewReader("t=tok&n=nonce"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(ChallengeRealIPHeader, "1.2.3.4")
	rr := roundtrip(cs, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	cookies := rr.Header()["Set-Cookie"]
	require.Len(t, cookies, 1)
	assert.Equal(t, "__crowdsec_challenge=abc123; HttpOnly; Path=/; SameSite=Lax", cookies[0])
}

func TestChallengeServer_MultipleSetCookieHeaders(t *testing.T) {
	cs, _ := newChallengeServerForTest(t, mockAppSecHandler(http.StatusForbidden, map[string]interface{}{
		"action":            "challenge",
		"http_status":       200,
		"user_body_content": "ok",
		"user_headers":      map[string][]string{},
		"user_cookies": []string{
			"__crowdsec_challenge=abc; HttpOnly",
			"session=xyz; Secure",
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.Header.Set(ChallengeRealIPHeader, "1.2.3.4")
	rr := roundtrip(cs, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	cookies := rr.Header()["Set-Cookie"]
	assert.Len(t, cookies, 2)
}

func TestChallengeServer_ReturnsOKWhenAppSecAllows(t *testing.T) {
	// AppSec returns 200 (allow) — the challenge server should pass through with 200 and empty body.
	cs, _ := newChallengeServerForTest(t, mockAppSecHandler(http.StatusOK, nil))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(ChallengeRealIPHeader, "1.2.3.4")
	rr := roundtrip(cs, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, rr.Body.String())
}

func TestChallengeServer_UsesRealIPHeader(t *testing.T) {
	var capturedIP string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIP = r.Header.Get("X-Crowdsec-Appsec-Ip")
		w.WriteHeader(http.StatusOK)
	})
	cs, _ := newChallengeServerForTest(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.Header.Set(ChallengeRealIPHeader, "203.0.113.42")
	roundtrip(cs, req)

	assert.Equal(t, "203.0.113.42", capturedIP)
}

func TestChallengeServer_FallsBackToRemoteAddrWhenNoRealIPHeader(t *testing.T) {
	var capturedIP string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIP = r.Header.Get("X-Crowdsec-Appsec-Ip")
		w.WriteHeader(http.StatusOK)
	})
	cs, _ := newChallengeServerForTest(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	// No ChallengeRealIPHeader set
	roundtrip(cs, req)

	assert.Equal(t, "203.0.113.5", capturedIP)
}

func TestChallengeServer_ForwardsRequestBodyToAppSec(t *testing.T) {
	var receivedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		// Return a challenge response so ServeHTTP doesn't return early
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"action": "challenge", "http_status": 200,
			"user_body_content": "ok", "user_headers": map[string][]string{},
			"user_cookies": []string{},
		})
	})
	cs, _ := newChallengeServerForTest(t, handler)

	payload := "t=ticket&n=nonce&p=salt&m=mac&f=fp&h=hmac&ts=123"
	req := httptest.NewRequest(http.MethodPost, "/crowdsec-internal/challenge/submit",
		strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(ChallengeRealIPHeader, "1.2.3.4")
	roundtrip(cs, req)

	assert.Equal(t, payload, string(receivedBody))
}

func TestChallengeServer_StripsRealIPHeaderBeforeForwarding(t *testing.T) {
	var capturedHeaders http.Header
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	cs, _ := newChallengeServerForTest(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(ChallengeRealIPHeader, "1.2.3.4")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	roundtrip(cs, req)

	assert.Empty(t, capturedHeaders.Get(ChallengeRealIPHeader),
		"X-Crowdsec-Real-Ip must not be forwarded to AppSec")
	assert.Empty(t, capturedHeaders.Get("X-Forwarded-For"),
		"X-Forwarded-For must not be forwarded to AppSec")
}

func TestChallengeServer_PowWorkerJSResponse(t *testing.T) {
	const workerJS = "// pow worker"

	cs, _ := newChallengeServerForTest(t, mockAppSecHandler(http.StatusForbidden, map[string]interface{}{
		"action":            "challenge",
		"http_status":       200,
		"user_body_content": workerJS,
		"user_headers": map[string][]string{
			"Content-Type":  {"application/javascript"},
			"Cache-Control": {"public, max-age=3600"},
		},
		"user_cookies": []string{},
	}))

	req := httptest.NewRequest(http.MethodGet, "/crowdsec-internal/challenge/pow-worker.js", nil)
	req.Header.Set(ChallengeRealIPHeader, "1.2.3.4")
	rr := roundtrip(cs, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/javascript", rr.Header().Get("Content-Type"))
	assert.Equal(t, "public, max-age=3600", rr.Header().Get("Cache-Control"))
	assert.Equal(t, workerJS, rr.Body.String())
}

func TestChallengeServer_InvalidSubmitResponse(t *testing.T) {
	cs, _ := newChallengeServerForTest(t, mockAppSecHandler(http.StatusForbidden, map[string]interface{}{
		"action":            "challenge",
		"http_status":       200,
		"user_body_content": `{"status":"failed"}`,
		"user_headers":      map[string][]string{"Content-Type": {"application/json"}, "Cache-Control": {"no-cache, no-store"}},
		"user_cookies":      []string{},
	}))

	req := httptest.NewRequest(http.MethodPost, "/crowdsec-internal/challenge/submit",
		strings.NewReader("t=bad&ts=bad&h=bad&n=bad&p=bad&m=bad&f=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(ChallengeRealIPHeader, "1.2.3.4")
	rr := roundtrip(cs, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"status":"failed"`)
}
