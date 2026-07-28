package spoa

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
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

	entryAny, ok := s.challengeResponses.Load(token)
	require.True(t, ok, "expected a cached challenge response for %q", token)

	entry, ok := entryAny.(*challengeResponseEntry)
	require.True(t, ok, "cached value for %q was not a *challengeResponseEntry", token)

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
	s := &Spoa{logger: log.NewEntry(log.New())}
	appSec := newChallengeAppSec(t, strings.Repeat("x", 150000))

	msgData := &HTTPMessageData{}
	writer := encoding.NewActionWriter(make([]byte, 1<<20), 0)

	got := s.validateWithAppSec(t.Context(), writer, msgData, nil, appSec, remediation.Allow, time.Second)

	assert.Equal(t, remediation.Ban, got)

	stored := false
	s.challengeResponses.Range(func(_, _ any) bool {
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
	s.challengeResponses.Range(func(_, _ any) bool {
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
