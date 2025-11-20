# crowdsec-spoa

[HAProxy SPOE](https://www.haproxy.com/blog/extending-haproxy-with-the-stream-processing-offload-engine) filter for CrowdSec - WAF and IP protection

## Table of Contents

- [crowdsec-spoa](#crowdsec-spoa)
  - [Table of Contents](#table-of-contents)
  - [About](#about)
  - [Roadmap](#roadmap)

## About

See  [public documentation](https://doc.crowdsec.net/u/bouncers/haproxy_spoa)

## Roadmap

This outlines the goals of the project, and the current status of each.

We are currently working on AppSec integration to this bouncer.

## Reload Support

The bouncer supports reloading host configurations without restarting the service. Use `systemctl reload crowdsec-spoa-bouncer` to reload hosts from both the main configuration file (`hosts:` section) and the `hosts_dir` directory. See [pkg/host/README.md](pkg/host/README.md) for detailed documentation.

**Note:** Only host configurations are reloadable. Changes to listener addresses, LAPI settings, or other configuration require a full service restart.
