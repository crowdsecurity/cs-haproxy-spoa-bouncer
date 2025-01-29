# crowdsec-spoa

[HAProxy SPOE](https://www.haproxy.com/blog/extending-haproxy-with-the-stream-processing-offload-engine) filter for CrowdSec - WAF and IP protection

## Table of Contents

- [crowdsec-spoa](#crowdsec-spoa)
  - [Table of Contents](#table-of-contents)
  - [About](#about)
  - [Roadmap](#roadmap)

## About

> [!NOTE]
> This is an experimental project, see [roadmap](#roadmap) for more details.

## Roadmap

This outlines the goals of the project, and the current status of each.

- [ ] **v0.1.0** - Initial release
  - [x] Container
    - [x] Dockerfile
    - [x] Docker Compose
  - [ ] Debian Package
    - [ ] Documentation
  - [ ] RPM Package
    - [ ] Documentation
  - [x] SPOA Server
    - [ ] TCP Listener
      - [ ] Documentation
      - [x] Configuration File
    - [ ] Unix Socket Listener
      - [ ] Documentation
      - [x] Configuration File
    - [ ] Handler
      - [ ] Documentation
  - [ ] Ban Remediation
    - [ ] Documentation
    - [x] Configuration File
    - [x] Template File
  - [ ] Captcha Remediation
    - [ ] Documentation
    - [x] Configuration File
    - [x] Template File
  - [ ] Country Remediation
    - [ ] Documentation
    - [x] Configuration File
  - [ ] AppSec
    - [ ] Documentation
    - [ ] Configuration File

HAProxy response schema

```
## Base variables
txn.crowdsec.remediation = "captcha" | "ban" | "unknown" | "allow"

## Ban variables
txn.crowdsec.contact_us_url = host.ban.contact_us_url

## Captcha variables
txn.crowdsec.captcha_site_key = host.captcha.site_key
txn.crowdsec.captcha_frontend_key = providers[host.provider].frontend_key
txn.crowdsec.captcha_frontend_js = providers[host.provider].frontend_js
```
