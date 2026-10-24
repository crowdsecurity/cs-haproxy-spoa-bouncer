package captcha

import "fmt"

// CustomProvider is a generic provider configured through the `custom` block, see CustomConfig.
const CustomProvider = "custom"

type infoProvider struct {
	js       string
	key      string
	validate string
}

var (
	HcaptchaProvider  = "hcaptcha"
	RecaptchaProvider = "recaptcha"
	TurnstileProvider = "turnstile"

	//nolint:gochecknoglobals
	providers = map[string]infoProvider{
		HcaptchaProvider: {
			js:       "https://hcaptcha.com/1/api.js",
			key:      "h-captcha",
			validate: "https://api.hcaptcha.com/siteverify",
		},
		RecaptchaProvider: {
			js:       "https://www.google.com/recaptcha/api.js",
			key:      "g-recaptcha",
			validate: "https://www.google.com/recaptcha/api/siteverify",
		},
		TurnstileProvider: {
			js:       "https://challenges.cloudflare.com/turnstile/v0/api.js",
			key:      "cf-turnstile",
			validate: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		},
	}
)

func ValidProvider(provider string) bool {
	if provider == CustomProvider {
		return true
	}

	_, ok := providers[provider]

	return ok
}

// providerSpec is everything the bouncer needs to display a captcha widget and verify its answer. It is
// resolved from either a built-in provider or the custom provider configuration.
type providerSpec struct {
	// frontend
	js            string // URL of the widget script
	jsType        string // type attribute of the script tag
	tag           string // HTML element rendering the widget
	class         string // CSS class of the widget element
	attrs         string // pre-rendered extra attributes of the widget element (HTML escaped)
	responseField string // form field holding the widget answer

	// backend
	verifyURL    string
	verifyFormat string
	custom       bool
}

// spec resolves the provider settings of the captcha configuration.
func (c *Captcha) spec() (providerSpec, error) {
	if c.Provider == CustomProvider {
		cc := &c.Custom

		return providerSpec{
			js:            cc.JSURL,
			jsType:        cc.scriptType(),
			tag:           cc.widgetTag(),
			class:         cc.WidgetClass,
			attrs:         cc.renderAttributes(),
			responseField: cc.responseField(),
			verifyURL:     cc.VerifyURL,
			verifyFormat:  cc.verifyFormat(),
			custom:        true,
		}, nil
	}

	p, ok := providers[c.Provider]
	if !ok {
		return providerSpec{}, fmt.Errorf("invalid captcha provider %s", c.Provider)
	}

	return providerSpec{
		js:            p.js,
		jsType:        scriptTypeClassic,
		tag:           defaultWidgetTag,
		class:         p.key,
		responseField: p.key + responseFieldSuffix,
		verifyURL:     p.validate,
		verifyFormat:  VerifyFormatForm,
	}, nil
}
