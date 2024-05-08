## Captcha

This pkg provides a way to bind captcha remediation to a [host](../host/README.md).

### Configuration

```yaml
hosts:
  - host: "*.example.com"
    captcha:
      site_key: "123"
      secret_key: "456"
      provider: "hcaptcha"
  - host: "*"
    captcha:
      fallback_remediation: allow
```

#### Keys

- `site_key` - The site key for the captcha provider
- `secret_key` - The secret key for the captcha provider
- `provider` - The provider to use, currently only `hcaptcha` | `recaptcha` | `turnstile` are supported
- `fallback_remediation` - The remediation to use if the captcha configuration is invalid, defaults to `ban`. Supported values are `ban` | `allow`, `allow` will allow the request to pass through without any remediation.

### Notes

Captcha configuration is only classed as invalid if the values are missing or the provider is not supported.
