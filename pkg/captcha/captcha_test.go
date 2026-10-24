package captcha

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSigningKey = "0123456789abcdef0123456789abcdef"

// newTestCaptcha builds an initialized Captcha. verifyURL may be empty for built-in providers.
func newTestCaptcha(t *testing.T, provider string, custom *CustomConfig) *Captcha {
	t.Helper()

	c := &Captcha{
		Provider:   provider,
		SiteKey:    "site",
		SecretKey:  "s3cr3t",
		SigningKey: testSigningKey,
		Custom:     *custom,
		Timeout:    2,
	}
	require.NoError(t, c.Init(log.NewEntry(log.New())))

	return c
}

// capCustom mimics the configuration used with a Cap instance.
func capCustom(verifyURL string) *CustomConfig {
	return &CustomConfig{
		VerifyURL:     verifyURL,
		VerifyFormat:  VerifyFormatJSON,
		JSURL:         "https://cap.example.com/assets/widget.js",
		JSModule:      true,
		ResponseField: "cap-response",
		WidgetTag:     "cap-widget",
		WidgetAttributes: map[string]string{
			"data-cap-api-endpoint":      "https://cap.example.com/abc/",
			"data-cap-hidden-field-name": "cap-response",
		},
	}
}

func TestBuiltinSpecUnchanged(t *testing.T) {
	for name, want := range map[string]struct{ js, class, field, verify string }{
		HcaptchaProvider:  {"https://hcaptcha.com/1/api.js", "h-captcha", "h-captcha-response", "https://api.hcaptcha.com/siteverify"},
		RecaptchaProvider: {"https://www.google.com/recaptcha/api.js", "g-recaptcha", "g-recaptcha-response", "https://www.google.com/recaptcha/api/siteverify"},
		TurnstileProvider: {"https://challenges.cloudflare.com/turnstile/v0/api.js", "cf-turnstile", "cf-turnstile-response", "https://challenges.cloudflare.com/turnstile/v0/siteverify"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestCaptcha(t, name, &CustomConfig{})

			spec, err := c.spec()
			require.NoError(t, err)
			assert.Equal(t, want.js, spec.js)
			assert.Equal(t, want.class, spec.class)
			assert.Equal(t, want.field, spec.responseField)
			assert.Equal(t, want.verify, spec.verifyURL)
			assert.Equal(t, VerifyFormatForm, spec.verifyFormat)
			assert.Equal(t, "div", spec.tag)
			assert.Equal(t, "text/javascript", spec.jsType)
			assert.Empty(t, spec.attrs)
			assert.False(t, spec.custom)

			assert.Equal(t, map[string]string{
				"captcha_site_key":         "site",
				"captcha_frontend_key":     want.class,
				"captcha_frontend_js":      want.js,
				"captcha_frontend_js_type": "text/javascript",
				"captcha_frontend_tag":     "div",
				"captcha_frontend_attrs":   "",
				"captcha_response_field":   want.field,
			}, c.frontendVars(&spec))

			assert.True(t, c.IsCaptchaSubmission(url.Values{want.field: {"x"}}.Encode()))
			assert.False(t, c.IsCaptchaSubmission(url.Values{"cap-response": {"x"}}.Encode()))
		})
	}
}

func TestBuiltinRejectsCustomSettings(t *testing.T) {
	c := &Captcha{
		Provider: HcaptchaProvider, SiteKey: "k", SecretKey: "s", SigningKey: testSigningKey,
		FallbackRemediation: "ban", Custom: CustomConfig{VerifyURL: "https://x.example.com/"},
	}
	err := c.IsValid()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "custom")
}

func TestInvalidProvider(t *testing.T) {
	assert.False(t, ValidProvider("nope"))
	assert.True(t, ValidProvider(CustomProvider))

	c := &Captcha{Provider: "nope"}
	_, err := c.spec()
	require.Error(t, err)
}

func TestCustomSpecAndFrontendVars(t *testing.T) {
	c := newTestCaptcha(t, CustomProvider, capCustom("https://cap.example.com/abc/siteverify"))

	spec, err := c.spec()
	require.NoError(t, err)
	assert.True(t, spec.custom)
	assert.Equal(t, "cap-widget", spec.tag)
	assert.Equal(t, "module", spec.jsType)
	assert.Equal(t, "cap-response", spec.responseField)
	assert.Equal(t, VerifyFormatJSON, spec.verifyFormat) //nolint:testifylint // not a JSON document, a format name

	vars := c.frontendVars(&spec)
	assert.Equal(t, "https://cap.example.com/assets/widget.js", vars["captcha_frontend_js"])
	assert.Equal(t, ` data-cap-api-endpoint="https://cap.example.com/abc/" data-cap-hidden-field-name="cap-response"`, vars["captcha_frontend_attrs"])
	assert.Equal(t, "cap-response", vars["captcha_response_field"])
	assert.Empty(t, vars["captcha_frontend_key"])

	assert.True(t, c.IsCaptchaSubmission("cap-response=tok"))
	assert.False(t, c.IsCaptchaSubmission("h-captcha-response=tok"))
	assert.False(t, c.IsCaptchaSubmission(""))
}

func TestCustomInitRequiresValidConfig(t *testing.T) {
	c := &Captcha{Provider: CustomProvider, SiteKey: "k", SecretKey: "s", SigningKey: testSigningKey}
	err := c.Init(log.NewEntry(log.New()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "custom.verify_url")
}

func TestEncodeVerifyRequest(t *testing.T) {
	body, ct, err := encodeVerifyRequest(VerifyFormatForm, "se&cret", "re sponse=")
	require.NoError(t, err)
	assert.Equal(t, "application/x-www-form-urlencoded", ct)
	v, err := url.ParseQuery(body)
	require.NoError(t, err)
	assert.Equal(t, "se&cret", v.Get("secret"))
	assert.Equal(t, "re sponse=", v.Get("response"))

	body, ct, err = encodeVerifyRequest(VerifyFormatJSON, `se"cret`, "resp")
	require.NoError(t, err)
	assert.Equal(t, "application/json", ct)
	var got map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.Equal(t, map[string]string{"secret": `se"cret`, "response": "resp"}, got)
}

// verifyServer starts a TLS server and points the captcha HTTP client at it.
func verifyServer(t *testing.T, format string, handler http.HandlerFunc) *Captcha {
	t.Helper()

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	cc := capCustom(srv.URL + "/abc/siteverify")
	cc.VerifyFormat = format
	c := newTestCaptcha(t, CustomProvider, cc)
	// Keep the client built by Init (timeout, redirect policy) and only trust the test server certificate.
	c.client.Transport = srv.Client().Transport

	return c
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = io.WriteString(w, body)
}

func TestValidateCustomJSON(t *testing.T) {
	var gotCT, gotAccept, gotMethod string
	var gotBody map[string]string

	c := verifyServer(t, VerifyFormatJSON, func(w http.ResponseWriter, r *http.Request) {
		gotCT, gotAccept, gotMethod = r.Header.Get("Content-Type"), r.Header.Get("Accept"), r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		writeJSON(w, `{"success":true}`)
	})

	ok, err := c.Validate(context.Background(), "uuid", "cap-response=the-token&other=1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "application/json", gotCT)
	assert.Equal(t, "application/json", gotAccept)
	assert.Equal(t, map[string]string{"secret": "s3cr3t", "response": "the-token"}, gotBody)
}

func TestValidateCustomForm(t *testing.T) {
	var got url.Values

	c := verifyServer(t, VerifyFormatForm, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		assert.NoError(t, r.ParseForm())
		got = r.PostForm
		writeJSON(w, `{"success":true}`)
	})

	ok, err := c.Validate(context.Background(), "uuid", "cap-response=tok%2Bwith%26chars")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "s3cr3t", got.Get("secret"))
	assert.Equal(t, "tok+with&chars", got.Get("response"))
}

func TestValidateCustomFailures(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		handler http.HandlerFunc
		wantErr string
	}{
		{name: "success false", body: "cap-response=t", handler: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, `{"success":false,"error-codes":["invalid-input-response"]}`)
		}, wantErr: "invalid-input-response"},
		{name: "success false no codes", body: "cap-response=t", handler: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, `{"success":false}`)
		}, wantErr: "without error codes"},
		{name: "missing success field", body: "cap-response=t", handler: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, `{}`)
		}, wantErr: "failed without error codes"},
		{name: "not json content type", body: "cap-response=t", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `{"success":true}`)
		}, wantErr: "content type"},
		{name: "invalid json", body: "cap-response=t", handler: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, `<html>`)
		}, wantErr: "decode"},
		{name: "http 500 html", body: "cap-response=t", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
		}, wantErr: "content type: text/html (HTTP 500)"},
		// Cap answers an unknown or already used token with 404 and a JSON body
		{name: "http 404 json success false", body: "cap-response=t", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"success":false,"error":"Token not found"}`)
		}, wantErr: "failed without error codes"},
		// wicketkeeper rejects a bad solution with http.Error (text/plain)
		{name: "http 403 plain text", body: "cap-response=t", handler: func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "proof-of-work hash mismatch", http.StatusForbidden)
		}, wantErr: "rejected by the verification endpoint (HTTP 403)"},
		{name: "http 404 plain text", body: "cap-response=t", handler: func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}, wantErr: "content type: text/plain; charset=utf-8 (HTTP 404)"},
		{name: "http 500 with success true", body: "cap-response=t", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"success":true}`)
		}, wantErr: "unexpected HTTP status 500"},
		{name: "http 403 with success true", body: "cap-response=t", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"success":true}`)
		}, wantErr: "unexpected HTTP status 403"},
		{name: "empty field", body: "cap-response=", handler: func(http.ResponseWriter, *http.Request) {
			t.Error("verification endpoint must not be called")
		}, wantErr: "empty captcha response"},
		{name: "wrong field", body: "h-captcha-response=t", handler: func(http.ResponseWriter, *http.Request) {
			t.Error("verification endpoint must not be called")
		}, wantErr: "empty captcha response"},
		{name: "empty body", body: "", handler: func(http.ResponseWriter, *http.Request) {
			t.Error("verification endpoint must not be called")
		}, wantErr: "empty captcha request body"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := verifyServer(t, VerifyFormatJSON, tc.handler)

			ok, err := c.Validate(context.Background(), "uuid", tc.body)
			assert.False(t, ok)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// A redirect must never be followed: the secret key is in the request body.
func TestValidateCustomRefusesRedirect(t *testing.T) {
	var targetHits atomic.Int32

	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		writeJSON(w, `{"success":true}`)
	}))
	defer target.Close()

	c := verifyServer(t, VerifyFormatJSON, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})

	ok, err := c.Validate(context.Background(), "uuid", "cap-response=t")
	assert.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect")
	assert.Zero(t, targetHits.Load())
}

func TestValidateCustomOversizedBody(t *testing.T) {
	c := verifyServer(t, VerifyFormatJSON, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"pad":"`)
		_, _ = io.WriteString(w, strings.Repeat("a", maxVerifyResponseBytes*2))
		_, _ = io.WriteString(w, `"}`)
	})

	ok, err := c.Validate(context.Background(), "uuid", "cap-response=t")
	assert.False(t, ok)
	require.Error(t, err, "a response larger than the limit must not be accepted")
	assert.Contains(t, err.Error(), "larger than")
}

// A valid JSON document followed by more data must not be accepted, whatever the size.
func TestValidateCustomTrailingData(t *testing.T) {
	for name, trailer := range map[string]string{
		"small":     "garbage",
		"oversized": strings.Repeat("a", maxVerifyResponseBytes*2),
	} {
		t.Run(name, func(t *testing.T) {
			c := verifyServer(t, VerifyFormatJSON, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"success":true}`+trailer)
			})

			ok, err := c.Validate(context.Background(), "uuid", "cap-response=t")
			assert.False(t, ok)
			require.Error(t, err)
		})
	}
}

func TestValidateContentTypeIsParsed(t *testing.T) {
	for _, ct := range []string{"application/jsonp", "text/plain; foo=application/json"} {
		t.Run(ct, func(t *testing.T) {
			c := verifyServer(t, VerifyFormatJSON, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", ct)
				_, _ = io.WriteString(w, `{"success":true}`)
			})

			ok, err := c.Validate(context.Background(), "uuid", "cap-response=t")
			assert.False(t, ok)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "content type")
		})
	}
}

// js_url and site_key are written in HTML attributes: an entity in them must not be decoded by the browser.
func TestFrontendVarsEscapeHTML(t *testing.T) {
	cc := capCustom("https://cap.example.com/abc/siteverify")
	cc.JSURL = "https://cap.example.com/w.js?a=1&copy;=2"
	c := newTestCaptcha(t, CustomProvider, cc)
	c.SiteKey = "k&amp;"

	spec, err := c.spec()
	require.NoError(t, err)
	vars := c.frontendVars(&spec)
	assert.Equal(t, "https://cap.example.com/w.js?a=1&amp;copy;=2", vars["captcha_frontend_js"])
	assert.Equal(t, "k&amp;amp;", vars["captcha_site_key"])
}

func TestValidateCustomTimeout(t *testing.T) {
	release := make(chan struct{})
	c := verifyServer(t, VerifyFormatJSON, func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		writeJSON(w, `{"success":true}`)
	})
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	ok, err := c.Validate(ctx, "uuid", "cap-response=t")
	assert.False(t, ok)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestValidateCustomLoopbackHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, `{"success":true}`)
	}))
	defer srv.Close()

	// httptest listens on 127.0.0.1: plain http is accepted without allow_insecure_http.
	cc := capCustom(srv.URL + "/verify")
	c := newTestCaptcha(t, CustomProvider, cc)

	ok, err := c.Validate(context.Background(), "uuid", "cap-response=t")
	require.NoError(t, err)
	assert.True(t, ok)
}

// The default HTTP client verifies certificates: an untrusted TLS server must be rejected.
func TestValidateCustomRejectsUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, `{"success":true}`)
	}))
	defer srv.Close()

	c := newTestCaptcha(t, CustomProvider, capCustom(srv.URL+"/verify"))

	valid, err := c.Validate(context.Background(), "uuid", "cap-response=t")
	assert.False(t, valid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509")
}

func TestSiteKeyOptionalOnlyForCustom(t *testing.T) {
	cc := validCustom()
	c := &Captcha{Provider: CustomProvider, SecretKey: "s", SigningKey: testSigningKey, FallbackRemediation: "ban", Custom: cc}
	require.NoError(t, c.IsValid())

	c = &Captcha{Provider: HcaptchaProvider, SecretKey: "s", SigningKey: testSigningKey, FallbackRemediation: "ban"}
	err := c.IsValid()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "site key")
}

func TestInvalidProviderMessageListsProviders(t *testing.T) {
	c := &Captcha{Provider: "nope"}
	err := c.IsValid()
	require.Error(t, err)

	for _, p := range []string{HcaptchaProvider, RecaptchaProvider, TurnstileProvider, CustomProvider} {
		assert.Contains(t, err.Error(), p)
	}
}

// Validate must not send the secret over plain http to a remote host, even if the caller skipped IsValid.
func TestValidateRevalidatesCustomConfig(t *testing.T) {
	c := newTestCaptcha(t, CustomProvider, capCustom("https://cap.example.com/v"))
	c.Custom.VerifyURL = "http://cap.example.com/v"

	ok, err := c.Validate(context.Background(), "uuid", "cap-response=t")
	assert.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https is required")
}

// Redirects are refused for the custom provider (the secret is in the request body), built-ins are unchanged.
func TestRedirectPolicy(t *testing.T) {
	custom := newTestCaptcha(t, CustomProvider, capCustom("https://cap.example.com/v"))
	require.NotNil(t, custom.client.CheckRedirect)

	builtin := newTestCaptcha(t, HcaptchaProvider, &CustomConfig{})
	assert.Nil(t, builtin.client.CheckRedirect)
}

// The shipped templates must use the variables of every provider.
func TestTemplatesUseProviderVariables(t *testing.T) {
	for _, path := range []string{"../../templates/captcha.html", "../../templates/lua/captcha.html"} {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)

		html := string(raw)
		for _, v := range []string{
			"captcha_frontend_js", "captcha_frontend_js_type", "captcha_frontend_tag",
			"captcha_frontend_key", "captcha_site_key", "captcha_frontend_attrs", "captcha_response_field",
		} {
			assert.Contains(t, html, v, "%s must use %s", path, v)
		}
	}
}
