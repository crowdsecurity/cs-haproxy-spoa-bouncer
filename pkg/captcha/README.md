## Captcha

This pkg provides a way to bind captcha remediation to a [host](../host/README.md).

**Note:** `signing_key` is required to sign captcha JWT cookies (HMAC-SHA256). It must be at least 32 bytes and should be different from the captcha provider `secret_key`.

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
      signing_key: "your-32-byte-minimum-secret-key-here"  # REQUIRED: Key for signing JWT tokens (minimum 32 bytes)
  - host: "*"
    captcha:
      fallback_remediation: allow
```

#### Keys

- `site_key` - The site key for the captcha provider
- `secret_key` - The secret key for the captcha provider
- `provider` - The provider to use: `hcaptcha` | `recaptcha` | `turnstile`, or `custom` to use any other "siteverify" style captcha (see [Custom provider](#custom-provider))
- `timeout` - HTTP client timeout in seconds for captcha validation requests (default: 5)
- `pending_ttl` - Time-to-live for pending captcha tokens. Accepts Go duration format (e.g., "30m", "1h", "2h30m"). Default: "30m"
- `passed_ttl` - Time-to-live for passed captcha tokens. Accepts Go duration format (e.g., "24h", "48h", "7d"). Default: "24h"
- `signing_key` - **REQUIRED**: Cryptographic key used for signing JWT captcha tokens (HMAC-SHA256). Must be at least 32 bytes. This must be explicitly configured and should be different from `secret_key` for compliance and security best practices. For multi-instance deployments, use the same `signing_key` across all instances to share tokens.

  To generate a secure random 32-byte secret using OpenSSL:
  ```bash
  openssl rand -hex 32
  ```
  
  This will generate a hex-encoded random string (64 characters = 32 bytes). For additional security, you can generate longer secrets (e.g., 64 bytes):
  ```bash
  openssl rand -hex 64
  ```
- `custom` - Settings of the `custom` provider, see [Custom provider](#custom-provider). Rejected for the other providers.
- `fallback_remediation` - The remediation to use if the captcha configuration is invalid, defaults to `ban`. Supported values are `ban` | `allow`, `allow` will allow the request to pass through without any remediation.

### Custom provider

`provider: custom` makes the bouncer work with any captcha following the "siteverify" convention used by hCaptcha, reCAPTCHA and Turnstile: the widget puts an opaque answer in a form field, and the bouncer sends it together with the `secret_key` to a verification endpoint that answers a JSON document containing `"success": true|false` (and optionally `"error-codes"`). This covers self-hosted and privacy-oriented captchas such as [Cap](https://capjs.js.org).

```yaml
captcha:
  provider: custom
  site_key: ""                  # optional with "custom"; exposed to the widget element as data-sitekey
  secret_key: "<secret>"        # sent to verify_url, never shown to the client
  signing_key: "<at least 32 bytes>"
  custom:
    verify_url: "https://captcha.example.com/<site key>/siteverify"  # required
    verify_format: json          # "form" (default, like the built-in providers) or "json"
    js_url: "https://captcha.example.com/assets/widget.js"           # required, absolute URL
    js_module: true              # load the script with type="module"
    response_field: "cap-token"      # name of the form field holding the answer (default: captcha-response)
    widget_tag: "cap-widget"     # element rendering the widget (default: div)
    widget_class: ""             # optional CSS class(es) on the widget element
    widget_attributes:           # optional extra attributes on the widget element
      data-cap-api-endpoint: "https://captcha.example.com/<site key>/"
    allow_insecure_http: false   # allow plain http for verify_url / js_url on a trusted network
```

The captcha page renders:

```html
<script src="{js_url}" type="module" async defer></script>
<cap-widget id="captcha" class="" data-sitekey="{site_key}" data-callback="captchaCallback" data-cap-api-endpoint="..."></cap-widget>
```

and submits the form when the widget fires `solve` (a `solve` event listener is part of the shipped `captcha.html` templates), or when it calls the global `captchaCallback` (the built-in providers' convention).

Keys of `custom`:

- `verify_url` - **required**. Verification endpoint. Must be `https`, unless `allow_insecure_http` is set or the host is a loopback address (`localhost`, `127.0.0.1`, `::1`). Redirects are never followed (the secret key is in the request body). The response must be a single JSON document (`Content-Type: application/json`) of at most 64 KiB; anything else is treated as a failure. `"success": true` is only accepted with HTTP 200, a rejection may use any status (Cap answers an invalid or already used token with 4xx). A plain text HTTP 400 or 403 is also treated as a rejection (wicketkeeper answers this way). The proxy settings of the environment (`HTTPS_PROXY`...) apply.
- `verify_format` - encoding of the verification request: `form` sends `secret` and `response` as `application/x-www-form-urlencoded`; `json` sends `{"secret": "...", "response": "..."}`. Default: `form`.
- `js_url` - **required**. Absolute URL of the widget script. It cannot be relative: the captcha page is served for every path of the protected host. Quotes, angle brackets, backslashes and whitespace must be percent-encoded. Pin a version when loading it from a CDN. With `js_module`, the script is fetched in CORS mode.
- `js_module` - load the script with `type="module"`, needed by widgets distributed as ES modules. Default: `false`.
- `response_field` - name of the form field the widget submits (`cap-token` for Cap). The captcha page waits for this field to be filled before submitting the form, and a POST containing it is treated as a captcha submission. Default: `captcha-response`.
- `widget_tag` - `div` or a lowercase custom element name, which contains a hyphen (e.g. `cap-widget`). Default: `div`.
- `widget_class` - CSS class(es) of the widget element, for widgets located by class name.
- `widget_attributes` - extra attributes of the widget element. Only lowercase `data-*` and `aria-*` attributes are accepted, except `data-sitekey` and `data-callback` which are managed by the bouncer. Values are HTML escaped and cannot contain line breaks or `{{`.
- `allow_insecure_http` - allow plain `http` for `verify_url` and `js_url`. For `js_url` this only makes sense if the protected site is itself served over http, browsers block mixed content. Default: `false`.

#### Using Cap

Cap's widget (`<cap-widget>`) creates a hidden `cap-token` input in the enclosing form and dispatches a `solve` event; the shipped templates listen to it and submit the form. Cap embeds its site key in the URLs, so `site_key` can stay empty. The Cap base URL appears in `verify_url`, `js_url` (when self-hosted) and `data-cap-api-endpoint`, keep them consistent. Check the exact verification request your instance expects on its `/swagger` page and set `verify_format` accordingly.

Things to check when the widget does not show up, all visible in the browser console:

- the Cap server answers CORS requests from the protected site (`/challenge` and `/redeem` are called from the page, and the module script is fetched in CORS mode),
- the Cap endpoint uses `https` when the protected site does (mixed content is blocked),
- the page is not given a strict `Content-Security-Policy` (the captcha page already uses inline script and style, and Cap needs `blob:` workers and WebAssembly).

#### Using wicketkeeper

[wicketkeeper](https://github.com/a-ve/wicketkeeper) is configured the same way as in the Traefik bouncer: its widget is a `div` located by class name and calls `data-callback`. Its client computes hashes with `crypto.subtle`, so the protected site must be served over https. wicketkeeper does not use a secret, but `secret_key` must still be set to any value.

```yaml
custom:
  verify_url: "https://captcha.example.com/v0/siteverify"
  js_url: "https://captcha.example.com/fast.js"   # client built from the wicketkeeper repository
  response_field: "wicketkeeper_solution"
  widget_class: "wicketkeeper"
  widget_attributes:
    data-challenge-url: "https://captcha.example.com/v0/challenge"
```

**Upgrading with customized templates:** if you copied `captcha.html` (or the Lua variant) to customize it, merge the new version: the old one does not render the widget tag, the script type, the extra attributes or the response field, so the `custom` provider will show an empty page (the built-in providers keep working).

### Notes

Captcha configuration is only classed as invalid if the values are missing or the provider is not supported. For the `custom` provider, an invalid `custom` block (bad URL, unsupported attribute, ...) is also reported, once, when the host configuration is loaded, and challenges then fall back to `fallback_remediation` (default `ban`). The configuration is not parsed strictly: a misspelled optional key is silently ignored.

Captcha validation requires the form body to be forwarded to the bouncer; see the HAProxy examples:
- [`config/haproxy.cfg`](../../config/haproxy.cfg)
- [`config/crowdsec.cfg`](../../config/crowdsec.cfg)
