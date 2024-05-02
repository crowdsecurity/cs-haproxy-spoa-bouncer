## Ban

This pkg provides a way to bind ban remediation to a [host](../host/README.md).

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

Please note this page is rendered to all so good chance that bots can scrape this link and use it to spam you. It is recommended to link to a separate contact form that not being protected by CrowdSec for example using a if check within the HAProxy configuration

```
spoe-message crowdsec-ip
    args id=unique-id src-ip=src src-port=src_port dst-ip=dst dst-port=dst_port headers=req.hdrs
    event on-frontend-http-request if !{ hdr(host) -m beg support.  }
```

This will only send the request to the SPOA server if the host header does not start with `support.`. This will allow you to have a separate contact form that is not protected by CrowdSec.
