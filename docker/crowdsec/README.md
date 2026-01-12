# CrowdSec Configuration for Docker Compose

This directory contains CrowdSec configuration files for testing the HAProxy SPOA bouncer with AppSec.

## Collections

The following collections are required for AppSec functionality:

- `crowdsecurity/appsec-virtual-patching` - Protection against known vulnerabilities
- `crowdsecurity/appsec-generic-rules` - Generic attack vector detection

These collections are automatically installed when the CrowdSec container starts via the `COLLECTIONS` environment variable in `docker-compose.yaml`.

## Acquisitions

The `acquisitions/appsec.yaml` file configures the AppSec Component to listen on port 7422 for HTTP request validation.

## Manual Collection Installation

If you need to manually install collections (e.g., when persisting `/etc/crowdsec/` on the host):

```bash
docker exec -it crowdsec cscli collections install crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
```

## AppSec Component

The AppSec Component listens on `0.0.0.0:7422` and can be accessed from other containers in the Docker network at `crowdsec:7422`.

