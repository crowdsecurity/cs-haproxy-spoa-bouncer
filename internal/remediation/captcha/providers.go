package captcha

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
	_, ok := providers[provider]
	return ok
}
