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
      signing_key: "your-32-byte-minimum-secret-key-here"  # REQUIRED: Key for signing JWT tokens (minimum 32 bytes) - breaking change in 0.3.0
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
- `signing_key` - **REQUIRED** (breaking change in 0.3.0): Cryptographic key used for signing JWT captcha tokens (HMAC-SHA256). Must be at least 32 bytes. This must be explicitly configured and should be different from `secret_key` for compliance and security best practices. For multi-instance deployments, use the same `signing_key` across all instances to share tokens.

  To generate a secure random 32-byte secret using OpenSSL:
  ```bash
  openssl rand -hex 32
  ```
  
  This will generate a hex-encoded random string (64 characters = 32 bytes). For additional security, you can generate longer secrets (e.g., 64 bytes):
  ```bash
  openssl rand -hex 64
  ```
- `fallback_remediation` - The remediation to use if the captcha configuration is invalid, defaults to `ban`. Supported values are `ban` | `allow`, `allow` will allow the request to pass through without any remediation.

### Notes

Captcha configuration is only classed as invalid if the values are missing or the provider is not supported.
