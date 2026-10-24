package captcha

import (
	"errors"
	"fmt"
	"html"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	// VerifyFormatForm sends the verification request as application/x-www-form-urlencoded.
	// This is what hCaptcha, reCAPTCHA and Turnstile expect, and is the default.
	VerifyFormatForm = "form"
	// VerifyFormatJSON sends the verification request as application/json.
	VerifyFormatJSON = "json"

	// DefaultCustomResponseField is the form field the custom provider reads the widget answer from
	// when `response_field` is not set.
	DefaultCustomResponseField = "captcha-response"

	defaultWidgetTag  = "div"
	scriptTypeClassic = "text/javascript"
	scriptTypeModule  = "module"
	// responseFieldSuffix is the suffix of the form field of the built-in providers (e.g. "h-captcha-response").
	responseFieldSuffix = "-response"

	// maxWidgetAttributesLen and maxURLLen cap the size of the values passed to HAProxy as transaction
	// variables on every captcha page view (they travel in a SPOE frame).
	maxWidgetAttributesLen = 2048
	maxURLLen              = 2048
)

//nolint:gochecknoglobals
var (
	// widgetTagRe matches "div" or a custom element name (e.g. "cap-widget"), which always contains a hyphen.
	widgetTagRe = regexp.MustCompile(`^(div|[a-z][a-z0-9]*(-[a-z0-9]+)+)$`)
	// widgetClassRe matches a space separated list of CSS classes.
	widgetClassRe = regexp.MustCompile(`^[A-Za-z0-9_ -]*$`)
	// attributeNameRe matches the attributes that can be set on the widget element: data-* and aria-*.
	attributeNameRe = regexp.MustCompile(`^(data|aria)-[a-z0-9][a-z0-9_.-]*$`)
	// responseFieldRe matches a form field name.
	responseFieldRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)

	// reservedWidgetAttributes are attributes the bouncer template sets itself.
	reservedWidgetAttributes = map[string]struct{}{
		"data-sitekey": {}, "data-callback": {},
	}
)

// CustomConfig describes a captcha widget that is not one of the built-in providers (hCaptcha,
// reCAPTCHA, Turnstile). It is used when `provider: custom` is set and lets the bouncer work with any
// widget following the "siteverify" convention: the widget puts an opaque answer in a form field, and the
// bouncer posts `secret` and `response` to a verification endpoint that answers `{"success": true|false}`.
// Self-hosted proof-of-work captchas such as Cap (https://capjs.js.org) fall in this category.
type CustomConfig struct {
	// VerifyURL is the server side verification endpoint. Required. Must be https, unless AllowInsecureHTTP
	// is set or the host is a loopback address.
	VerifyURL string `yaml:"verify_url"`
	// VerifyFormat is the encoding of the verification request body: "form" (default) or "json".
	VerifyFormat string `yaml:"verify_format"`
	// JSURL is the URL of the widget script loaded by the captcha page. Required. It must be an absolute
	// URL: the captcha page is served for every path of the protected host, so a relative path would
	// itself be answered with the captcha page.
	JSURL string `yaml:"js_url"`
	// JSModule loads the widget script with type="module" (needed by web components distributed as ES modules).
	JSModule bool `yaml:"js_module"`
	// ResponseField is the name of the form field holding the widget answer, as submitted by the captcha page
	// form. Default: "captcha-response".
	ResponseField string `yaml:"response_field"`
	// WidgetTag is the HTML element that renders the widget. Default: "div".
	WidgetTag string `yaml:"widget_tag"`
	// WidgetClass is the CSS class(es) added to the widget element, for widgets located by class name.
	WidgetClass string `yaml:"widget_class"`
	// WidgetAttributes are extra HTML attributes set on the widget element. Only data-* and aria-* attributes
	// are accepted. Values are HTML escaped.
	WidgetAttributes map[string]string `yaml:"widget_attributes"`
	// AllowInsecureHTTP allows plain http URLs for verify_url and js_url (for a verification service
	// reachable on a trusted internal network). Loopback hosts are always allowed for verify_url.
	AllowInsecureHTTP bool `yaml:"allow_insecure_http"`
}

// isZero reports whether no custom setting was provided.
func (cc *CustomConfig) isZero() bool {
	return cc.VerifyURL == "" && cc.VerifyFormat == "" && cc.JSURL == "" && !cc.JSModule &&
		cc.ResponseField == "" && cc.WidgetTag == "" && cc.WidgetClass == "" &&
		len(cc.WidgetAttributes) == 0 && !cc.AllowInsecureHTTP
}

// validate checks the custom provider settings.
func (cc *CustomConfig) validate() error {
	if cc.VerifyURL == "" {
		return errors.New("custom captcha provider requires custom.verify_url")
	}

	verifyURL, err := parseEndpointURL("custom.verify_url", cc.VerifyURL)
	if err != nil {
		return err
	}

	// The secret key is sent to verify_url: plain http is only accepted if it cannot leave the machine,
	// or if explicitly allowed.
	if verifyURL.Scheme == "http" && !cc.AllowInsecureHTTP && !isLoopbackHost(verifyURL.Hostname()) {
		return errInsecureHTTP("custom.verify_url", cc.VerifyURL)
	}

	if cc.JSURL == "" {
		return errors.New("custom captcha provider requires custom.js_url")
	}

	jsURL, err := parseEndpointURL("custom.js_url", cc.JSURL)
	if err != nil {
		return err
	}

	if jsURL.Scheme == "http" && !cc.AllowInsecureHTTP {
		return errInsecureHTTP("custom.js_url", cc.JSURL)
	}

	switch cc.VerifyFormat {
	case "", VerifyFormatForm, VerifyFormatJSON:
	default:
		return fmt.Errorf("invalid custom.verify_format %q, supported values are %q and %q", cc.VerifyFormat, VerifyFormatForm, VerifyFormatJSON)
	}

	if field := cc.responseField(); !responseFieldRe.MatchString(field) {
		return fmt.Errorf("invalid custom.response_field %q: it must be a plain form field name (letters, digits, '-', '_' or '.')", field)
	}

	tag := cc.widgetTag()
	if !widgetTagRe.MatchString(tag) {
		return fmt.Errorf("invalid custom.widget_tag %q: it must be \"div\" or a custom element name such as \"cap-widget\"", tag)
	}

	if !widgetClassRe.MatchString(cc.WidgetClass) {
		return fmt.Errorf("invalid custom.widget_class %q", cc.WidgetClass)
	}

	return cc.validateAttributes()
}

func (cc *CustomConfig) validateAttributes() error {
	for name, value := range cc.WidgetAttributes {
		if !attributeNameRe.MatchString(name) {
			return fmt.Errorf("invalid custom.widget_attributes name %q: only lowercase data-* and aria-* attributes are supported", name)
		}

		if _, reserved := reservedWidgetAttributes[name]; reserved {
			return fmt.Errorf("custom.widget_attributes %q is not allowed: it is managed by the bouncer", name)
		}

		// The page template is rendered with "{{name}}" substitutions by the Lua variant, and line based
		// "{{ if }}" handling: keep values on one line and free of template markers.
		if strings.ContainsAny(value, "\r\n") || strings.Contains(value, "{{") {
			return fmt.Errorf("invalid custom.widget_attributes value for %q: line breaks and \"{{\" are not allowed", name)
		}
	}

	if len(cc.renderAttributes()) > maxWidgetAttributesLen {
		return fmt.Errorf("custom.widget_attributes is too large (maximum %d bytes once rendered)", maxWidgetAttributesLen)
	}

	return nil
}

func (cc *CustomConfig) responseField() string {
	if cc.ResponseField == "" {
		return DefaultCustomResponseField
	}

	return cc.ResponseField
}

func (cc *CustomConfig) widgetTag() string {
	if cc.WidgetTag == "" {
		return defaultWidgetTag
	}

	return cc.WidgetTag
}

func (cc *CustomConfig) verifyFormat() string {
	if cc.VerifyFormat == "" {
		return VerifyFormatForm
	}

	return cc.VerifyFormat
}

func (cc *CustomConfig) scriptType() string {
	if cc.JSModule {
		return scriptTypeModule
	}

	return scriptTypeClassic
}

// renderAttributes renders the extra widget attributes as an HTML fragment (` name="value" name2="value2"`),
// sorted by name so the output is deterministic. Names are validated, values are HTML escaped.
func (cc *CustomConfig) renderAttributes() string {
	if len(cc.WidgetAttributes) == 0 {
		return ""
	}

	names := make([]string, 0, len(cc.WidgetAttributes))
	for name := range cc.WidgetAttributes {
		names = append(names, name)
	}

	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, " "+name+`="`+html.EscapeString(cc.WidgetAttributes[name])+`"`)
	}

	return strings.Join(parts, "")
}

func errInsecureHTTP(field, raw string) error {
	return fmt.Errorf("invalid %s %q: https is required (set custom.allow_insecure_http to allow plain http)", field, raw)
}

// parseEndpointURL checks that raw is an absolute http(s) URL without credentials or fragment, and that
// it can safely be written in an HTML attribute.
func parseEndpointURL(field, raw string) (*url.URL, error) {
	if len(raw) > maxURLLen {
		return nil, fmt.Errorf("invalid %s: URL is too long (maximum %d bytes)", field, maxURLLen)
	}

	// js_url is rendered inside an HTML attribute: refuse anything that could end it, or that is not
	// valid in a URL anyway. Use percent-encoding.
	if strings.ContainsAny(raw, "\"'`<>\\") || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, fmt.Errorf("invalid %s: quotes, angle brackets, backslashes, whitespace and control characters must be percent-encoded", field)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}

	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid %s %q: it must be an absolute URL", field, raw)
	}

	if u.User != nil {
		return nil, fmt.Errorf("invalid %s: credentials in the URL are not allowed", field)
	}

	if u.Fragment != "" {
		return nil, fmt.Errorf("invalid %s: URL fragments are not allowed", field)
	}

	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("invalid %s %q: unsupported scheme %q", field, raw, u.Scheme)
	}

	return u, nil
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}
