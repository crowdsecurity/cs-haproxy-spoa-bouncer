## Host

This pkg provides a way to configure multiple hosts that may be using this SPOA server.

### Configuration

```yaml
hosts:
  - host: "*.example.com"
    ban:
      contact_us_url: "mailto:"
    captcha:
        site_key: "123"
        secret_key: "456"
        provider: "hcaptcha"
```

#### Keys

- `host` - The host to bind the configuration to, supports wildcards
- `ban` - The ban remediation configuration [README](../ban/README.md)
- `captcha` - The captcha remediation configuration [README](../captcha/README.md)

### Notes

#### First Match System

The order of the hosts in the configuration file matters, the first match will be used. So if you want to use different captcha for the same domain, you will need to create multiple entries for the subdomains.

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

#### Catch all configuration

If you are using this as a hosting provider you may want to provide a catch for all domains. You can use the `*` wildcard to match all domains. However, keep in mind the first match system, so this should always be the last entry in the configuration file.

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

This is why we recommend having a catch-all configuration for the `ban` remediation it will allow you to change the `fallback_remediation` to `none` or provide a `contact_us_url`. As this will impact user experience if they are not able to contact anyone for help.
