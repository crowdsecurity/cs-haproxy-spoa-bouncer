package spoa

import (
	"bytes"
	"context"
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
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
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
		challengeRelays:         newChallengeRelayCache(0),
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

func storeTestChallengeRelay(t *testing.T, s *Spoa, appSecToUse *appsec.AppSec) string {
	t.Helper()

	token := "relay-token"
	s.challengeRelays.Store(token, challengeRelayEntry{
		appSec:    appSecToUse,
		timeout:   time.Second,
		expiresAt: time.Now().Add(time.Minute),
	})
	return token
}

func newChallengeRelayURIRecorder(t *testing.T) (*Spoa, *string) {
	t.Helper()

	var gotURI string
	a := &appsec.AppSec{URL: "http://appsec.test/", APIKey: "test-key"}
	require.NoError(t, a.Init(log.NewEntry(log.New())))
	a.Client.HTTPClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotURI = req.Header.Get("X-Crowdsec-Appsec-Uri")
		respBody, err := json.Marshal(map[string]any{
			"action":            "challenge",
			"http_status":       200,
			"user_body_content": "<html>challenge</html>",
		})
		require.NoError(t, err)

		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(respBody)),
		}, nil
	})

	return &Spoa{
		logger:             log.NewEntry(log.New()),
		dataset:            dataset.New(),
		geoDatabase:        &geo.GeoDatabase{},
		globalAppSec:       a,
		challengeResponses: newChallengeCache(0),
		challengeRelays:    newChallengeRelayCache(0),
	}, &gotURI
}

func TestNewChallengeHTTPServerSetsTimeouts(t *testing.T) {
	s := newTestSpoa(t)

	server := s.newChallengeHTTPServer()

	assert.NotNil(t, server.Handler)
	assert.Equal(t, 5*time.Second, server.ReadHeaderTimeout)
	assert.Equal(t, 10*time.Second, server.ReadTimeout)
	assert.Equal(t, 10*time.Second, server.WriteTimeout)
	assert.Equal(t, 30*time.Second, server.IdleTimeout)
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

func newCountingChallengeAppSecTransport(t *testing.T, body string, calls *int32) http.RoundTripper {
	t.Helper()

	respBody, err := json.Marshal(map[string]any{
		"action":            "challenge",
		"http_status":       200,
		"user_body_content": body,
	})
	require.NoError(t, err)

	return roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		atomic.AddInt32(calls, 1)
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(respBody)),
		}, nil
	})
}

func newCountingChallengeAppSec(t *testing.T, body string, calls *int32) appsec.AppSec {
	t.Helper()

	a := appsec.AppSec{URL: "http://appsec.test/", APIKey: "test-key"}
	require.NoError(t, a.Init(log.NewEntry(log.New())))
	a.Client.HTTPClient.Transport = newCountingChallengeAppSecTransport(t, body, calls)

	return a
}

func TestValidateWithAppSec_ChallengeWithoutHTTPBackend_FallsBackToBan(t *testing.T) {
	s := &Spoa{logger: log.NewEntry(log.New()), challengeResponses: newChallengeCache(0), challengeRelays: newChallengeRelayCache(0)}
	appSec := newChallengeAppSec(t, strings.Repeat("x", 150000))

	msgData := &HTTPMessageData{}
	writer := encoding.NewActionWriter(make([]byte, 1<<20), 0)

	got, issued := s.validateWithAppSec(t.Context(), writer, msgData, nil, appSec, remediation.Allow, time.Second)

	assert.Equal(t, remediation.Ban, got)
	assert.False(t, issued)

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

	got, issued := s.validateWithAppSec(t.Context(), writer, msgData, nil, appSec, remediation.Allow, time.Second)

	assert.Equal(t, remediation.Ban, got)
	assert.False(t, issued)

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

	got, issued := s.validateWithAppSec(t.Context(), writer, msgData, nil, appSec, remediation.Allow, time.Second)

	require.Equal(t, remediation.Challenge, got)
	assert.True(t, issued)

	actions := decodeSetVarActions(t, writer.Bytes())
	require.Contains(t, actions, "challenge_url")
	assert.True(t, strings.HasPrefix(actions["challenge_url"].str, challengePathPrefix))

	token := strings.TrimPrefix(actions["challenge_url"].str, challengePathPrefix)
	assert.Equal(t, s.challengeTokenFromRequestID("req-abc"), token)
	entry := loadChallengeEntry(t, s, token)
	assert.Equal(t, body, entry.body)
}

func TestValidateWithAppSec_ChallengeStoresRelayWithoutMutatingInternalURLs(t *testing.T) {
	s := newTestSpoa(t)
	body := `<script src="/crowdsec-internal/challenge/worker.js"></script><form action="/crowdsec-internal/challenge/submit"></form>`
	appSec := newChallengeAppSec(t, body)

	msgData := &HTTPMessageData{
		ID:   ptr.Of("req-rewrite"),
		Host: ptr.Of("protected.example.com"),
	}
	writer := encoding.NewActionWriter(make([]byte, 1<<20), 0)

	got, issued := s.validateWithAppSec(t.Context(), writer, msgData, nil, appSec, remediation.Allow, time.Second)

	require.Equal(t, remediation.Challenge, got)
	assert.True(t, issued)

	token := s.challengeTokenFromRequestID("req-rewrite")
	entry := loadChallengeEntry(t, s, token)
	assert.Equal(t, body, entry.body)

	relay, ok := s.challengeRelays.Load(token)
	require.True(t, ok)
	assert.Same(t, appSec, relay.appSec)
	assert.Equal(t, "protected.example.com", relay.host)
}

func TestValidateWithAppSec_ChallengeWithEmptyBody_FallsBackToBan(t *testing.T) {
	s := newTestSpoa(t)
	appSec := newChallengeAppSec(t, "")

	msgData := &HTTPMessageData{ID: ptr.Of("req-empty-body")}
	writer := encoding.NewActionWriter(make([]byte, 1<<20), 0)

	got, issued := s.validateWithAppSec(t.Context(), writer, msgData, nil, appSec, remediation.Allow, time.Second)

	require.Equal(t, remediation.Ban, got)
	assert.False(t, issued)

	actions := decodeSetVarActions(t, writer.Bytes())
	assert.NotContains(t, actions, "challenge_url")
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
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 2)
	assert.Equal(t, "crowdsec_cookie", cookies[0].Name)
	require.Equal(t, challengeRelayCookieName, cookies[1].Name)
	assert.Equal(t, "tok", cookies[1].Value)
	assert.Equal(t, challengeInternalPathPrefix, cookies[1].Path)
	assert.True(t, cookies[1].HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookies[1].SameSite)

	_, ok := s.challengeResponses.Load("tok")
	assert.False(t, ok)
}

func TestHandleStoredChallengeHTTP_ExpiredEntryReturnsNotFound(t *testing.T) {
	s := newTestSpoa(t)
	s.challengeResponses.Store("tok", &challengeResponseEntry{
		status: http.StatusOK,
		body:   "stale challenge body",
		// Already expired: LoadAndDelete will still find it (the cleanup sweep
		// hasn't reclaimed it yet), but it must not be served.
		expiresAt: time.Now().Add(-time.Second),
	})

	req := httptest.NewRequest(http.MethodGet, challengePathPrefix+"tok", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleStoredChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), "stale challenge body")

	_, ok := s.challengeResponses.Load("tok")
	assert.False(t, ok, "an expired entry should still be consumed (LoadAndDelete) even though it isn't served")
}

func TestSweepExpiredChallengeResponses_RemovesOnlyExpiredEntries(t *testing.T) {
	s := newTestSpoa(t)
	now := time.Now()

	s.challengeResponses.Store("expired", &challengeResponseEntry{body: "old", expiresAt: now.Add(-time.Second)})
	s.challengeResponses.Store("fresh", &challengeResponseEntry{body: "new", expiresAt: now.Add(time.Minute)})

	s.sweepExpiredChallengeResponses(now)

	_, ok := s.challengeResponses.Load("expired")
	assert.False(t, ok, "expired entry should have been reclaimed by the sweep")

	fresh, ok := s.challengeResponses.Load("fresh")
	require.True(t, ok, "non-expired entry should survive the sweep")
	assert.Equal(t, "new", fresh.body)
}

func TestCleanupChallengeResponses_StopsOnContextCancel(t *testing.T) {
	s := newTestSpoa(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		s.cleanupChallengeResponses(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanupChallengeResponses did not return promptly after context cancellation")
	}
}

func TestSweepExpiredChallengeRelays_RemovesOnlyExpiredEntries(t *testing.T) {
	s := newTestSpoa(t)
	appSec := newChallengeAppSec(t, "<html>challenge</html>")
	now := time.Now()

	s.challengeRelays.Store("expired", challengeRelayEntry{appSec: appSec, timeout: time.Second, expiresAt: now.Add(-time.Second)})
	s.challengeRelays.Store("fresh", challengeRelayEntry{appSec: appSec, timeout: time.Second, expiresAt: now.Add(time.Minute)})

	s.sweepExpiredChallengeRelays(now)

	_, ok := s.challengeRelays.Load("expired")
	assert.False(t, ok)

	relay, ok := s.challengeRelays.Load("fresh")
	require.True(t, ok)
	assert.Same(t, appSec, relay.appSec)
}

// newInternalChallengeSpoa builds a Spoa wired for handleInternalChallengeHTTP tests,
// with a real dataset/geo database and an AppSec double that counts calls.
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
		challengeRelays:    newChallengeRelayCache(0),
	}
	return s, &calls
}

func TestHandleInternalChallengeHTTP_MissingRelayTokenReturnsNotFound(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.7")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(calls), "AppSec must not be reached without an issued challenge token")
}

func TestHandleInternalChallengeHTTP_UnknownRelayCookieReturnsNotFound(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.AddCookie(newChallengeRelayCookie("unknown-token"))
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.7")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(calls), "AppSec must not be reached with an unknown challenge relay cookie")
}

func TestHandleInternalChallengeHTTP_BannedIPRejectedWithoutCallingAppSec(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	token := storeTestChallengeRelay(t, s, s.globalAppSec)
	s.dataset.Add(models.GetDecisionsResponse{
		{
			Scope:  ptr.Of("IP"),
			Value:  ptr.Of("203.0.113.5"),
			Type:   ptr.Of("ban"),
			Origin: ptr.Of("test"),
		},
	})

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	// Client-supplied header must NOT be trusted for the ban check either -
	// only the HAProxy-set X-Crowdsec-Real-Src should be honored.
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Crowdsec-Real-Src", "203.0.113.5")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(calls), "a banned IP must not reach the AppSec engine through this endpoint")
}

// A captcha decision must not block challenge traffic: a captcha'd IP can be solving an
// AppSec challenge, whose assets and proof submission all land on this endpoint.
func TestHandleInternalChallengeHTTP_CaptchaIPStillRelaysToAppSec(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	token := storeTestChallengeRelay(t, s, s.globalAppSec)
	s.dataset.Add(models.GetDecisionsResponse{
		{
			Scope:  ptr.Of("IP"),
			Value:  ptr.Of("203.0.113.6"),
			Type:   ptr.Of("captcha"),
			Origin: ptr.Of("test"),
		},
	})

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Crowdsec-Real-Src", "203.0.113.6")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "<html>challenge</html>")
	assert.Equal(t, int32(1), atomic.LoadInt32(calls), "a captcha'd IP must still be able to complete an AppSec challenge")
}

func TestHandleInternalChallengeHTTP_DatasetChallengeRejectedWithoutCallingAppSec(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	token := storeTestChallengeRelay(t, s, s.globalAppSec)
	s.dataset.Add(models.GetDecisionsResponse{
		{
			Scope:  ptr.Of("IP"),
			Value:  ptr.Of("203.0.113.7"),
			Type:   ptr.Of("challenge"),
			Origin: ptr.Of("test"),
		},
	})

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Crowdsec-Real-Src", "203.0.113.7")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(calls), "a dataset-level challenge remediation must not reach AppSec through the internal relay")
}

func TestHandleInternalChallengeHTTP_AllowedIPRelaysToAppSec(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	token := storeTestChallengeRelay(t, s, s.globalAppSec)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.7")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "<html>challenge</html>")
	assert.Equal(t, int32(1), atomic.LoadInt32(calls), "a non-banned IP should still be relayed to AppSec")
}

func TestHandleInternalChallengeHTTP_RelayCookieRelaysBareInternalPath(t *testing.T) {
	s, gotURI := newChallengeRelayURIRecorder(t)
	token := storeTestChallengeRelay(t, s, s.globalAppSec)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"pow-worker.js?v=1", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.12")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "/crowdsec-internal/challenge/pow-worker.js?v=1", *gotURI)
}

func TestHandleInternalChallengeHTTP_TokenizedInternalURLWithoutCookieReturnsNotFound(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	token := storeTestChallengeRelay(t, s, s.globalAppSec)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+token+"/worker.js", http.NoBody)
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.12")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(calls), "tokenized internal URLs are not accepted without the relay cookie")
}

func TestHandleInternalChallengeHTTP_RelayCookieKeepsPathUnchangedForAppSec(t *testing.T) {
	s, gotURI := newChallengeRelayURIRecorder(t)
	token := storeTestChallengeRelay(t, s, s.globalAppSec)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"worker.js?v=1", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.12")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "/crowdsec-internal/challenge/worker.js?v=1", *gotURI)
}

func TestHandleInternalChallengeHTTP_DoesNotMutateRelayedChallengeAssets(t *testing.T) {
	const assetBody = `const worker = "/crowdsec-internal/challenge/pow-worker.js";`

	a := &appsec.AppSec{URL: "http://appsec.test/", APIKey: "test-key"}
	require.NoError(t, a.Init(log.NewEntry(log.New())))
	a.Client.HTTPClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		respBody, err := json.Marshal(map[string]any{
			"action":            "challenge",
			"http_status":       200,
			"user_body_content": assetBody,
			"user_headers": map[string][]string{
				"Content-Type": {"application/javascript"},
			},
		})
		require.NoError(t, err)
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
		challengeRelays:    newChallengeRelayCache(0),
	}
	token := storeTestChallengeRelay(t, s, a)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"fpscanner.js", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.12")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/javascript", rec.Header().Get("Content-Type"))
	assert.Equal(t, assetBody, rec.Body.String())
}

// A solved challenge is AppSec answering 200 with the proof cookie the browser
// replays on its retry. The relay must hand that response back untouched - if the
// cookie is dropped the browser has nothing to replay and gets challenged forever.
func TestHandleInternalChallengeHTTP_SolvedChallengeForwardsAppSecResponse(t *testing.T) {
	const (
		proofCookie = "__crowdsec_challenge_passed=abc123; Path=/; HttpOnly; SameSite=Lax"
		proofBody   = `{"status":"ok"}`
	)

	a := &appsec.AppSec{URL: "http://appsec.test/", APIKey: "test-key"}
	require.NoError(t, a.Init(log.NewEntry(log.New())))
	a.Client.HTTPClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"Set-Cookie":   []string{proofCookie},
			},
			Body: io.NopCloser(strings.NewReader(proofBody)),
		}, nil
	})

	s := &Spoa{
		logger:             log.NewEntry(log.New()),
		dataset:            dataset.New(),
		geoDatabase:        &geo.GeoDatabase{},
		globalAppSec:       a,
		challengeResponses: newChallengeCache(0),
		challengeRelays:    newChallengeRelayCache(0),
	}
	token := storeTestChallengeRelay(t, s, a)

	req := httptest.NewRequest(http.MethodPost, challengeInternalPathPrefix+"validate", strings.NewReader("proof=solved"))
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.10")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{proofCookie}, rec.Result().Header.Values("Set-Cookie"))
	assert.JSONEq(t, proofBody, rec.Body.String(), "AppSec's response body must be forwarded to the client")
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

// AppSec rejecting the relayed request outright must not leak its JSON decision
// envelope to the browser.
func TestHandleInternalChallengeHTTP_BanFromAppSecReturnsPlainForbidden(t *testing.T) {
	a := &appsec.AppSec{URL: "http://appsec.test/", APIKey: "test-key"}
	require.NoError(t, a.Init(log.NewEntry(log.New())))
	a.Client.HTTPClient.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"action":"ban","http_status":403}`)),
		}, nil
	})

	s := &Spoa{
		logger:             log.NewEntry(log.New()),
		dataset:            dataset.New(),
		geoDatabase:        &geo.GeoDatabase{},
		globalAppSec:       a,
		challengeResponses: newChallengeCache(0),
		challengeRelays:    newChallengeRelayCache(0),
	}
	token := storeTestChallengeRelay(t, s, a)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.11")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContains(t, rec.Body.String(), "action")
}

func TestHandleInternalChallengeHTTP_RelayTokenPinsAppSecConfig(t *testing.T) {
	var hostCalls int32
	var globalCalls int32

	globalAppSec := newCountingChallengeAppSec(t, "<html>global challenge</html>", &globalCalls)

	hostManager := host.NewManager(log.NewEntry(log.New()))
	matchedHost := &host.Host{
		Host: "protected.example.com",
		AppSec: appsec.AppSec{
			URL:    "http://appsec.test/",
			APIKey: "test-key",
		},
	}
	hostManager.AddHost(matchedHost)
	matchedHost.AppSec.Client.HTTPClient.Transport = newCountingChallengeAppSecTransport(t, "<html>host challenge</html>", &hostCalls)

	s := &Spoa{
		logger:             log.NewEntry(log.New()),
		dataset:            dataset.New(),
		geoDatabase:        &geo.GeoDatabase{},
		hostManager:        hostManager,
		globalAppSec:       &globalAppSec,
		challengeResponses: newChallengeCache(0),
		challengeRelays:    newChallengeRelayCache(0),
	}
	token := "relay-token"
	s.challengeRelays.Store(token, challengeRelayEntry{
		appSec:    &matchedHost.AppSec,
		timeout:   time.Second,
		host:      matchedHost.Host,
		expiresAt: time.Now().Add(time.Minute),
	})

	req := httptest.NewRequest(http.MethodGet, "http://other.example.com"+challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.8")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "<html>host challenge</html>")
	assert.Equal(t, int32(1), atomic.LoadInt32(&hostCalls))
	assert.Equal(t, int32(0), atomic.LoadInt32(&globalCalls), "relay must use the AppSec config stored with the issued token, not the request Host")
}

func TestHandleInternalChallengeHTTP_SpoofedXForwardedForIgnoredForBanCheck(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	token := storeTestChallengeRelay(t, s, s.globalAppSec)
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
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.Header.Set("X-Crowdsec-Real-Src", "198.51.100.50")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	// The banned IP was only ever claimed via X-Forwarded-For, which is not trusted
	// here; the HAProxy-set X-Crowdsec-Real-Src is, and it is not banned, so the
	// request is relayed - proving the spoofed value was neither checked nor forwarded.
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))
}

// Without X-Crowdsec-Real-Src the visitor's IP is unknowable here, since RemoteAddr is
// HAProxy. So the request is refused rather than relayed with the wrong source.
func TestHandleInternalChallengeHTTP_MissingRealSrcFailsClosed(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	token := storeTestChallengeRelay(t, s, s.globalAppSec)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.RemoteAddr = "198.51.100.50:12345"
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(calls), "AppSec must not be reached with an unknown client IP")
}

func TestHandleInternalChallengeHTTP_UnparseableRealSrcFailsClosed(t *testing.T) {
	s, calls := newInternalChallengeSpoa(t)
	token := storeTestChallengeRelay(t, s, s.globalAppSec)

	req := httptest.NewRequest(http.MethodGet, challengeInternalPathPrefix+"asset.js", http.NoBody)
	req.AddCookie(newChallengeRelayCookie(token))
	req.Header.Set("X-Crowdsec-Real-Src", "not-an-ip")
	rec := httptest.NewRecorder()

	s.handleInternalChallengeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(calls), "AppSec must not be reached with an unparseable client IP")
}

func TestTrustedChallengeClientIP(t *testing.T) {
	t.Run("uses X-Crowdsec-Real-Src when present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Crowdsec-Real-Src", "203.0.113.9")
		req.RemoteAddr = "127.0.0.1:9100"

		got, ok := trustedChallengeClientIP(req)
		assert.True(t, ok)
		assert.Equal(t, "203.0.113.9", got)
	})

	t.Run("reports failure rather than falling back when the header is absent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.RemoteAddr = "192.0.2.1:54321"

		got, ok := trustedChallengeClientIP(req)
		assert.False(t, ok, "RemoteAddr is HAProxy, never the visitor - it must not be used as a fallback")
		assert.Empty(t, got)
	})
}
