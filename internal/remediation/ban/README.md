## Ban

This pkg provides a way to bind ban remediation to a [host](../../../pkg/host/README.md).

Related docs:
- Host matching and per-host config: [`pkg/host/README.md`](../../../pkg/host/README.md)
- Captcha remediation: [`pkg/captcha/README.md`](../../../pkg/captcha/README.md)
- HAProxy examples: [`config/haproxy.cfg`](../../../config/haproxy.cfg), [`config/crowdsec.cfg`](../../../config/crowdsec.cfg)

### Configuration

```yaml
hosts:
  - host: "*.example.com"
    ban:
      contact_us_url: "mailto:support@example.com?subject=CrowdSec%20Ban%20Page%20Help"
```

#### Keys

- `contact_us_url` - The URL which is bound to a `contact us` link in the ban page

## Notes

### Contact Us URL

If the `contact_us_url` is not set, the `contact us` link will not be displayed on the ban page.

Please note this page is rendered to all blocked clients, so bots can scrape this link and use it to spam you. Consider linking to a contact form that is protected separately (for example, a dedicated support site with its own bot protections).

If you want a support host to avoid HTTP inspection by this bouncer, you can skip sending the HTTP SPOE groups for that host:

```haproxy
acl is_support hdr(host) -m beg support.
http-request send-spoe-group crowdsec crowdsec-http-body if !is_support
http-request send-spoe-group crowdsec crowdsec-http-no-body if !is_support
```

If you need a support host to bypass CrowdSec decisions entirely (including the early IP check), run it on a separate listener/frontend without the `filter spoe engine crowdsec ...` line.
