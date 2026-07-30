package spoa

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSpoa(t *testing.T) *Spoa {
	t.Helper()

	return &Spoa{
		logger:                  log.NewEntry(log.New()),
		ChallengeHTTPListenAddr: dummyListener{},
		challengeTokenKey:       [32]byte{1, 2, 3},
		challengeResponses:      newChallengeCache(0),
	}
}

type dummyListener struct{}

func (dummyListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (dummyListener) Close() error              { return nil }
func (dummyListener) Addr() net.Addr            { return dummyAddr("127.0.0.1:9100") }

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

func loadChallengeEntry(t *testing.T, s *Spoa, token string) *challengeResponseEntry {
	t.Helper()

	entry, ok := s.challengeResponses.Load(token)
	require.True(t, ok, "expected a cached challenge response for %q", token)

	return entry
}

// decodedAction is a test-only decoding of a single SET-VAR action written by
// an ActionWriter, used to assert on what handlers actually sent back to
// HAProxy without needing HAProxy itself.
type decodedAction struct {
	str   string
	boolV bool
}

func decodeSetVarActions(t *testing.T, data []byte) map[string]decodedAction {
	t.Helper()

	const (
		dataTypeMask = 0x0F
		dataFlagTrue = 0x10
		dtBool       = 1
		dtInt64      = 4
		dtString     = 8
		dtBinary     = 9
	)

	result := map[string]decodedAction{}
	off := 0
	for off < len(data) {
		off += 2 // action type + nb-args
		off++    // scope
		nameLen, n, err := encoding.Varint(data[off:])
		require.NoError(t, err)
		off += n
		name := string(data[off : off+int(nameLen)])
		off += int(nameLen)

		dtByte := data[off]
		off++
		dt := dtByte & dataTypeMask

		var da decodedAction
		switch dt {
		case dtString, dtBinary:
			l, n, err := encoding.Varint(data[off:])
			require.NoError(t, err)
			off += n
			da.str = string(data[off : off+int(l)])
			off += int(l)
		case dtBool:
			da.boolV = dtByte&dataFlagTrue != 0
		case dtInt64:
			_, n, err := encoding.Varint(data[off:])
			require.NoError(t, err)
			off += n
		default:
			t.Fatalf("decodeSetVarActions: unsupported datatype %d for key %q", dt, name)
		}
		result[name] = da
	}
	return result
}

// newChallengeAppSec spins up a test AppSec server that always issues a
// challenge with the given body, and returns an *appsec.AppSec wired to it.
func newChallengeAppSec(t *testing.T, body string) *appsec.AppSec {
	t.Helper()

	respBody, err := json.Marshal(map[string]any{
		"action":            "challenge",
		"http_status":       200,
		"user_body_content": body,
	})
	require.NoError(t, err)

	a := &appsec.AppSec{URL: "http://appsec.test/", APIKey: "test-key"}
	require.NoError(t, a.Init(log.NewEntry(log.New())))
	a.Client.HTTPClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(respBody)),
		}, nil
	})
	return a
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestValidateWithAppSec_ChallengeWithoutHTTPBackend_FallsBackToBan(t *testing.T) {
	s := &Spoa{logger: log.NewEntry(log.New()), challengeResponses: newChallengeCache(0)}
	appSec := newChallengeAppSec(t, strings.Repeat("x", 150000))

	msgData := &HTTPMessageData{}
	writer := encoding.NewActionWriter(make([]byte, 1<<20), 0)

	got := s.validateWithAppSec(t.Context(), writer, msgData, nil, appSec, remediation.Allow, time.Second)

	assert.Equal(t, remediation.Ban, got)

	stored := false
	s.challengeResponses.Range(func(_ string, _ *challengeResponseEntry) bool {
		stored = true
		return false
	})
	assert.False(t, stored, "no challenge response should be cached without an HTTP backend")
}

func TestValidateWithAppSec_ChallengeWithoutUniqueID_FallsBackToBan(t *testing.T) {
	s := newTestSpoa(t)
	appSec := newChallengeAppSec(t, strings.Repeat("x", 150000))

	msgData := &HTTPMessageData{}
	writer := encoding.NewActionWriter(make([]byte, 1<<20), 0)

	got := s.validateWithAppSec(t.Context(), writer, msgData, nil, appSec, remediation.Allow, time.Second)

	assert.Equal(t, remediation.Ban, got)

	stored := false
	s.challengeResponses.Range(func(_ string, _ *challengeResponseEntry) bool {
		stored = true
		return false
	})
	assert.False(t, stored, "no challenge response should be cached without a unique request id")
}

func TestValidateWithAppSec_ChallengeStoresResponseAndSetsURL(t *testing.T) {
	s := newTestSpoa(t)
	body := strings.Repeat("x", 150000)
	appSec := newChallengeAppSec(t, body)

	msgData := &HTTPMessageData{ID: ptr.Of("req-abc")}
	writer := encoding.NewActionWriter(make([]byte, 1<<20), 0)

	got := s.validateWithAppSec(t.Context(), writer, msgData, nil, appSec, remediation.Allow, time.Second)

	require.Equal(t, remediation.Challenge, got)

	actions := decodeSetVarActions(t, writer.Bytes())
	require.Contains(t, actions, "challenge_url")
	assert.True(t, strings.HasPrefix(actions["challenge_url"].str, challengePathPrefix))

	token := strings.TrimPrefix(actions["challenge_url"].str, challengePathPrefix)
	assert.Equal(t, s.challengeTokenFromRequestID("req-abc"), token)
	entry := loadChallengeEntry(t, s, token)
	assert.Equal(t, body, entry.body)
}

func TestValidateWithAppSec_ChallengeWithEmptyBody_StoresFallbackBody(t *testing.T) {
	s := newTestSpoa(t)
	appSec := newChallengeAppSec(t, "")

	msgData := &HTTPMessageData{ID: ptr.Of("req-empty-body")}
	writer := encoding.NewActionWriter(make([]byte, 1<<20), 0)

	got := s.validateWithAppSec(t.Context(), writer, msgData, nil, appSec, remediation.Allow, time.Second)

	require.Equal(t, remediation.Challenge, got)

	actions := decodeSetVarActions(t, writer.Bytes())
	require.Contains(t, actions, "challenge_url")

	token := strings.TrimPrefix(actions["challenge_url"].str, challengePathPrefix)
	entry := loadChallengeEntry(t, s, token)
	assert.Contains(t, entry.body, "Request challenged by CrowdSec")
	assert.Contains(t, entry.headers.Values("Content-Type"), "text/html; charset=utf-8")
}

func TestHandleStoredChallengeHTTP_ServesAndDeletesCachedResponse(t *testing.T) {
	s := newTestSpoa(t)
	s.challengeResponses.Store("tok", &challengeResponseEntry{
		status:    http.StatusAccepted,
		body:      "challenge body",
		headers:   http.Header{"Content-Type": []string{"text/html"}},
		cookies:   []string{"crowdsec_cookie=value; Path=/"},
		expiresAt: time.Now().Add(time.Minute),
	})

	req := httptest.NewRequest(http.MethodGet, challengePathPrefix+"tok", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleStoredChallengeHTTP(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)
	assert.Equal(t, "challenge body", rec.Body.String())
	assert.Equal(t, "text/html", rec.Header().Get("Content-Type"))
	assert.Equal(t, "crowdsec_cookie=value; Path=/", rec.Header().Get("Set-Cookie"))

	_, ok := s.challengeResponses.Load("tok")
	assert.False(t, ok)
}

// newInternalChallengeSpoa builds a Spoa with a real dataset/geo database (as
// production always provides, per cmd/root.go) wired up for
// handleInternalChallengeHTTP tests, plus an AppSec double that counts calls
// so tests can assert whether AppSec was reached at all.
func newInternalChallengeSpoa(t *testing.T) (*Spoa, *int32) {
	t.Helper()

	const appSecBody = "<html>challenge</html>"

	var calls int32
	respBody, err := json.Marshal(map[string]any{
		"action":            "challenge",
		"http_status":       200,
		"user_body_content": appSecBody,
	})
	require.NoError(t, err)

	a := &appsec.AppSec{URL: "http://appsec.test/", APIKey: "test-key"}
	require.NoError(t, a.Init(log.NewEntry(log.New())))
	a.Client.HTTPClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		atomic.AddInt32(&calls, 1)
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(respBody)),
		}, nil
	})

	s := &Spoa{
		logger:             log.NewEntry(log.New()),
		dataset:            dataset.New(),
		geoDatabase:        &geo.GeoDatabase{},
		globalAppSec:       a,
		challengeResponses: newChallengeCache(0),
	}
	return s, &calls
}

func TestHandleInternalChallengeHTTP_BannedIPRejectedWithoutCallingAppSec(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	s.dataset.Add(models.GetDecisionsResponse{
		{
			Scope:  ptr.Of("IP"),
			Value:  ptr.Of("203.0.113.5"),
			Type:   ptr.Of("ban"),
			Origin: ptr.Of("test"),
		},
	})

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	// Client-supplied header must NOT be trusted for the ban check either -
	// only the HAProxy-set X-Crowdsec-Real-Src should be honored.
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Crowdsec-Real-Src", "203.0.113.5")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(calls), "a banned IP must not reach the AppSec engine through this endpoint")
}

func TestHandleInternalChallengeHTTP_CaptchaPendingIPRejectedWithoutCallingAppSec(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	s.dataset.Add(models.GetDecisionsResponse{
		{
			Scope:  ptr.Of("IP"),
			Value:  ptr.Of("203.0.113.6"),
			Type:   ptr.Of("captcha"),
			Origin: ptr.Of("test"),
		},
	})

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.Header.Set("X-Crowdsec-Real-Src", "203.0.113.6")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(calls), "a captcha-pending IP must not reach the AppSec engine through this endpoint")
}

// TestHandleInternalChallengeHTTP_DatasetChallengeRemediationStillRelayed guards
// against re-introducing rem >= remediation.Captcha (Challenge sorts above
// Captcha in the ordering, so that comparison would also block it). If the
// dataset itself already resolved this IP to "challenge" (e.g. a decision with
// Type "challenge" added via cscli/LAPI), that's exactly the case this relay
// exists to serve - AppSec is the authority on what to do with it next, not a
// reason to 403 before ever asking AppSec.
func TestHandleInternalChallengeHTTP_DatasetChallengeRemediationStillRelayed(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	s.dataset.Add(models.GetDecisionsResponse{
		{
			Scope:  ptr.Of("IP"),
			Value:  ptr.Of("203.0.113.7"),
			Type:   ptr.Of("challenge"),
			Origin: ptr.Of("test"),
		},
	})

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.Header.Set("X-Crowdsec-Real-Src", "203.0.113.7")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(1), atomic.LoadInt32(calls), "a dataset-level challenge remediation must still be relayed to AppSec")
}

func TestHandleInternalChallengeHTTP_AllowedIPRelaysToAppSec(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.7")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "<html>challenge</html>")
	assert.Equal(t, int32(1), atomic.LoadInt32(calls), "a non-banned IP should still be relayed to AppSec")
}

func TestHandleInternalChallengeHTTP_SpoofedXForwardedForIgnoredForBanCheck(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	// Ban a victim IP; the attacker tries to get it "reported" as their own
	// source by spoofing X-Forwarded-For, without HAProxy setting the trusted header.
	s.dataset.Add(models.GetDecisionsResponse{
		{
			Scope:  ptr.Of("IP"),
			Value:  ptr.Of("203.0.113.99"),
			Type:   ptr.Of("ban"),
			Origin: ptr.Of("test"),
		},
	})

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.RemoteAddr = "198.51.100.50:12345"
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	// Since X-Crowdsec-Real-Src is absent, trustedChallengeClientIP falls back to
	// RemoteAddr (198.51.100.50), which is not banned, so the request is relayed -
	// proving the spoofed X-Forwarded-For value was not the one checked or forwarded.
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))
}

func TestTrustedChallengeClientIP(t *testing.T) {
	t.Run("uses X-Crowdsec-Real-Src when present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Crowdsec-Real-Src", "203.0.113.9")
		req.RemoteAddr = "127.0.0.1:9100"

		assert.Equal(t, "203.0.113.9", trustedChallengeClientIP(req))
	})

	t.Run("falls back to RemoteAddr when header absent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.RemoteAddr = "192.0.2.1:54321"

		assert.Equal(t, "192.0.2.1", trustedChallengeClientIP(req))
	})
}
