## Host

This pkg provides a way to configure multiple hosts that may be using this SPOA server.

Related docs:
- Captcha configuration (providers, keys, token cookie settings): [`pkg/captcha/README.md`](../captcha/README.md)
- Ban page templating and variables: [`internal/remediation/ban/README.md`](../../internal/remediation/ban/README.md)

### Configuration

```yaml
hosts:
  - host: "*.example.com"
    ban:
      contact_us_url: "mailto:"
    captcha:
      provider: "hcaptcha"
      # See pkg/captcha/README.md for full captcha settings
    appsec:
      url: "http://127.0.0.1:7422/" # optional
```

#### Keys

- `host` - The host to bind the configuration to, supports wildcards
- `ban` - Ban remediation configuration: [`internal/remediation/ban/README.md`](../../internal/remediation/ban/README.md)
- `captcha` - Captcha remediation configuration: [`pkg/captcha/README.md`](../captcha/README.md)
- `appsec` - Optional CrowdSec AppSec validation configuration (HTTP-only)

### Notes

#### Match priority (automatic)

Host patterns are sorted so the most specific match wins:

- Patterns without `*` are preferred over wildcard patterns.
- Within each group, longer patterns are preferred over shorter patterns.

Avoid overlapping patterns with the same specificity/length, as the ordering between them is not meaningful.

```yaml
hosts:
  - host: "www.example.com"
    captcha:
      site_key: "123"
      secret_key: "456"
      provider: "hcaptcha"
  - host: "*example.com"
    captcha:
      site_key: "789"
      secret_key: "012"
      provider: "recaptcha"
```

In this example, `www.example.com` will use `hcaptcha` and all other subdomains of `example.com` will use `recaptcha`.

#### Catch-all configuration

If you are using this as a hosting provider you may want to provide a catch-all for all domains. You can use the `*` wildcard to match all domains; it will naturally be one of the lowest-priority patterns.

```yaml
hosts:
  - host: "www.example.com"
    captcha:
      site_key: "123"
      secret_key: "456"
      provider: "hcaptcha"
  - host: "*"
    ban:
      contact_us_url: "mailto:support@hostmasters.com"
```

#### What happens if no host is found?

If no host is found for the incoming request, then the remediation will be sent "as is" with one caveat.

If the remediation is `captcha` and no host is found, then the remediation will be automatically changed to a `ban` since we have no way to display the captcha.

This is why we recommend having a catch-all configuration for the `ban` remediation: it lets you provide a `contact_us_url` and/or tune captcha `fallback_remediation` (see the docs above), which helps user experience when a domain doesn’t match any host rule.
