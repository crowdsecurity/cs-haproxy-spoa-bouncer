package captcha

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// validCustom returns a minimal valid custom configuration.
func validCustom() CustomConfig {
	return CustomConfig{
		VerifyURL: "https://cap.example.com/abc/siteverify",
		JSURL:     "https://cap.example.com/assets/widget.js",
	}
}

func TestCustomConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*CustomConfig)
		wantErr string
	}{
		{name: "minimal", mutate: func(*CustomConfig) {}},
		{name: "full", mutate: func(c *CustomConfig) {
			c.VerifyFormat = VerifyFormatJSON
			c.JSModule = true
			c.ResponseField = "cap-response"
			c.WidgetTag = "cap-widget"
			c.WidgetClass = "a b-c"
			c.WidgetAttributes = map[string]string{"data-cap-api-endpoint": "https://cap.example.com/abc/"}
		}},
		{name: "missing verify_url", mutate: func(c *CustomConfig) { c.VerifyURL = "" }, wantErr: "custom.verify_url"},
		{name: "missing js_url", mutate: func(c *CustomConfig) { c.JSURL = "" }, wantErr: "custom.js_url"},
		{name: "relative js_url", mutate: func(c *CustomConfig) { c.JSURL = "/widget.js" }, wantErr: "absolute"},
		{name: "http verify_url", mutate: func(c *CustomConfig) { c.VerifyURL = "http://cap.example.com/v" }, wantErr: "https is required"},
		{name: "http verify_url allowed", mutate: func(c *CustomConfig) {
			c.VerifyURL = "http://cap.internal/v"
			c.AllowInsecureHTTP = true
		}},
		{name: "http loopback verify_url", mutate: func(c *CustomConfig) { c.VerifyURL = "http://127.0.0.1:3000/v" }},
		{name: "http localhost verify_url", mutate: func(c *CustomConfig) { c.VerifyURL = "http://localhost:3000/v" }},
		{name: "http js_url loopback is not exempt", mutate: func(c *CustomConfig) { c.JSURL = "http://127.0.0.1/w.js" }, wantErr: "https is required"},
		{name: "ftp scheme", mutate: func(c *CustomConfig) { c.VerifyURL = "ftp://cap.example.com/v" }, wantErr: "unsupported scheme"},
		{name: "javascript scheme", mutate: func(c *CustomConfig) { c.JSURL = "javascript:alert(1)" }, wantErr: "custom.js_url"},
		{name: "credentials in url", mutate: func(c *CustomConfig) { c.VerifyURL = "https://u:p@cap.example.com/v" }, wantErr: "credentials"},
		{name: "fragment in url", mutate: func(c *CustomConfig) { c.JSURL = "https://cap.example.com/w.js#x" }, wantErr: "fragment"},
		{name: "bad verify_format", mutate: func(c *CustomConfig) { c.VerifyFormat = "xml" }, wantErr: "verify_format"},
		{name: "response_field cap default", mutate: func(c *CustomConfig) { c.ResponseField = "cap-token" }},
		{name: "response_field with space", mutate: func(c *CustomConfig) { c.ResponseField = "my token-response" }, wantErr: "response_field"},
		{name: "response_field with ampersand", mutate: func(c *CustomConfig) { c.ResponseField = "a&b-response" }, wantErr: "response_field"},
		{name: "tag uppercase", mutate: func(c *CustomConfig) { c.WidgetTag = "Div" }, wantErr: "widget_tag"},
		{name: "tag injection", mutate: func(c *CustomConfig) { c.WidgetTag = "div onclick=x" }, wantErr: "widget_tag"},
		{name: "tag script", mutate: func(c *CustomConfig) { c.WidgetTag = "script" }, wantErr: "widget_tag"},
		{name: "tag span", mutate: func(c *CustomConfig) { c.WidgetTag = "span" }, wantErr: "widget_tag"},
		{name: "class injection", mutate: func(c *CustomConfig) { c.WidgetClass = `x" onclick="y` }, wantErr: "widget_class"},
		{name: "attr aria allowed", mutate: func(c *CustomConfig) { c.WidgetAttributes = map[string]string{"aria-label": "captcha"} }},
		{name: "attr bad name", mutate: func(c *CustomConfig) { c.WidgetAttributes = map[string]string{`a b`: "x"} }, wantErr: "widget_attributes"},
		{name: "attr quote in name", mutate: func(c *CustomConfig) { c.WidgetAttributes = map[string]string{`data-a"b`: "x"} }, wantErr: "widget_attributes"},
		{name: "attr event handler", mutate: func(c *CustomConfig) { c.WidgetAttributes = map[string]string{"onclick": "x()"} }, wantErr: "data-* and aria-*"},
		{name: "attr non data", mutate: func(c *CustomConfig) { c.WidgetAttributes = map[string]string{"xlink:href": "x"} }, wantErr: "data-* and aria-*"},
		{name: "attr autofocus", mutate: func(c *CustomConfig) { c.WidgetAttributes = map[string]string{"autofocus": ""} }, wantErr: "data-* and aria-*"},
		{name: "attr reserved", mutate: func(c *CustomConfig) { c.WidgetAttributes = map[string]string{"data-sitekey": "x"} }, wantErr: "managed by the bouncer"},
		{name: "attr value template marker", mutate: func(c *CustomConfig) { c.WidgetAttributes = map[string]string{"data-a": "{{captcha_site_key}}"} }, wantErr: "not allowed"},
		{name: "attr value newline", mutate: func(c *CustomConfig) { c.WidgetAttributes = map[string]string{"data-a": "a\n{{ end }}"} }, wantErr: "not allowed"},
		{name: "js_url attribute breakout", mutate: func(c *CustomConfig) { c.JSURL = `https://a.example/w.js" onerror="alert(1)` }, wantErr: "percent-encoded"},
		{name: "js_url angle brackets", mutate: func(c *CustomConfig) { c.JSURL = "https://a.example/w.js?x=<script>" }, wantErr: "percent-encoded"},
		{name: "js_url whitespace", mutate: func(c *CustomConfig) { c.JSURL = "https://a.example/w .js" }, wantErr: "percent-encoded"},
		{name: "js_url percent encoded", mutate: func(c *CustomConfig) { c.JSURL = "https://a.example/w.js?x=%22%3E" }},
		{name: "js_url too long", mutate: func(c *CustomConfig) { c.JSURL = "https://a.example/" + strings.Repeat("a", maxURLLen) }, wantErr: "too long"},
		{name: "attr too large", mutate: func(c *CustomConfig) {
			c.WidgetAttributes = map[string]string{"data-x": strings.Repeat("a", maxWidgetAttributesLen)}
		}, wantErr: "too large"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cc := validCustom()
			tc.mutate(&cc)

			err := cc.validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestCustomConfigDefaults(t *testing.T) {
	cc := validCustom()
	assert.Equal(t, DefaultCustomResponseField, cc.responseField())
	assert.Equal(t, "div", cc.widgetTag())
	assert.Equal(t, VerifyFormatForm, cc.verifyFormat())
	assert.Equal(t, "text/javascript", cc.scriptType())

	cc.JSModule = true
	cc.VerifyFormat = VerifyFormatJSON
	assert.Equal(t, "module", cc.scriptType())
	assert.Equal(t, VerifyFormatJSON, cc.verifyFormat()) //nolint:testifylint // not a JSON document, a format name
}

func TestRenderAttributes(t *testing.T) {
	cc := CustomConfig{}
	assert.Empty(t, cc.renderAttributes())

	cc.WidgetAttributes = map[string]string{
		"data-z": "last",
		"data-a": `he said "hi" & <left>`,
		"data-p": "100%",
	}
	// sorted by name, values escaped, % left untouched (HAProxy lf-file only interprets %[...] / %{...})
	assert.Equal(t,
		` data-a="he said &#34;hi&#34; &amp; &lt;left&gt;" data-p="100%" data-z="last"`,
		cc.renderAttributes())
}

func TestIsZero(t *testing.T) {
	assert.True(t, (&CustomConfig{}).isZero())
	assert.False(t, (&CustomConfig{JSModule: true}).isZero())
	assert.False(t, (&CustomConfig{AllowInsecureHTTP: true}).isZero())
	assert.False(t, (&CustomConfig{WidgetAttributes: map[string]string{"a": "b"}}).isZero())
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "LOCALHOST": true, "127.0.0.1": true, "::1": true, "127.5.5.5": true,
		"10.0.0.1": false, "example.com": false, "localhost.example.com": false,
	} {
		assert.Equal(t, want, isLoopbackHost(host), host)
	}
}

func TestCustomConfigYAML(t *testing.T) {
	doc := `
provider: custom
site_key: sitekey
secret_key: secret
signing_key: 0123456789abcdef0123456789abcdef
fallback_remediation: ban
custom:
  verify_url: https://cap.example.com/abc/siteverify
  verify_format: json
  js_url: https://cdn.jsdelivr.net/npm/@cap.js/widget@0.1.26
  js_module: true
  response_field: cap-response
  widget_tag: cap-widget
  widget_class: cap
  widget_attributes:
    data-cap-api-endpoint: https://cap.example.com/abc/
    data-cap-hidden-field-name: cap-response
  allow_insecure_http: false
`
	var c Captcha
	require.NoError(t, yaml.Unmarshal([]byte(doc), &c))

	assert.Equal(t, CustomProvider, c.Provider)
	assert.Equal(t, "https://cap.example.com/abc/siteverify", c.Custom.VerifyURL)
	assert.Equal(t, VerifyFormatJSON, c.Custom.VerifyFormat) //nolint:testifylint // not a JSON document, a format name
	assert.True(t, c.Custom.JSModule)
	assert.Equal(t, "cap-response", c.Custom.ResponseField)
	assert.Equal(t, "cap-widget", c.Custom.WidgetTag)
	assert.Equal(t, "cap", c.Custom.WidgetClass)
	assert.Equal(t, "cap-response", c.Custom.WidgetAttributes["data-cap-hidden-field-name"])
	assert.Len(t, c.Custom.WidgetAttributes, 2)
	require.NoError(t, c.IsValid())
}
