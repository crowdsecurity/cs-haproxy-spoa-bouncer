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
      timeout: 10  # HTTP client timeout in seconds (default: 5)
      pending_ttl: "30m"  # TTL for pending captcha tokens (default: 30m)
      passed_ttl: "24h"   # TTL for passed captcha tokens (default: 24h)
      cookie_secret: "optional-secret"  # Secret for signing cookies (defaults to secret_key)
  - host: "*"
    captcha:
      fallback_remediation: allow
```

#### Keys

- `site_key` - The site key for the captcha provider
- `secret_key` - The secret key for the captcha provider
- `provider` - The provider to use, currently only `hcaptcha` | `recaptcha` | `turnstile` are supported
- `timeout` - HTTP client timeout in seconds for captcha validation requests (default: 5)
- `pending_ttl` - Time-to-live for pending captcha tokens. Accepts Go duration format (e.g., "30m", "1h", "2h30m"). Default: "30m"
- `passed_ttl` - Time-to-live for passed captcha tokens. Accepts Go duration format (e.g., "24h", "48h", "7d"). Default: "24h"
- `cookie_secret` - Secret key used for signing captcha cookies. If not set, defaults to `secret_key`. This allows you to use a different secret for cookie signing than for captcha provider validation.
- `fallback_remediation` - The remediation to use if the captcha configuration is invalid, defaults to `ban`. Supported values are `ban` | `allow`, `allow` will allow the request to pass through without any remediation.

### Notes

Captcha configuration is only classed as invalid if the values are missing or the provider is not supported.
