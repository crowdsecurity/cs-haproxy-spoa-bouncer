<div align="center">
  <img src="img/crowdsec_haproxy.svg" alt="CrowdSec HAProxy" width="400"/>
</div>

# CrowdSec HAProxy SPOA Bouncer

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A lightweight Stream Processing Offload Agent (SPOA) that contacts the CrowdSec Local API to fetch decisions in real time while aiming to be highly performant and minimize latency for clients. It manages an in-memory cache of bans and captchas, and directs HAProxy on how to treat each connection without blocking the data path.

## At a Glance

- **Real-time enforcement** – Streams decisions from CrowdSec via the Go bouncer SDK so ban/captcha/allow changes are visible within seconds.
- **HTTP and TCP coverage** – Handles the `crowdsec-ip`, `crowdsec-http`, and `crowdsec-tcp` SPOE messages to protect both web frontends and raw TCP services.
- **Host-aware responses** – Each host entry can customize ban pages, captcha providers, and logging while sharing the same SPOA worker.
- **Captcha challenges built in** – hCaptcha, reCAPTCHA, and Cloudflare Turnstile are supported with signed cookies so solved challenges can be verified without round-tripping to the provider.
- **Memory-efficient dataset** – IPs live in a lock-free map and CIDRs are stored in a [BART](https://github.com/gaissmai/bart) radix tree, which keeps lookups in the tens of nanoseconds.
- **Optional GeoIP tagging** – Plug in MaxMind ASN/City databases to enrich decisions with ISO country codes for templating or ACLs.
- **Operational visibility** – Structured logging, Prometheus counters, and an optional pprof endpoint make it easy to monitor and debug the bouncer.
- **Optional AppSec validation** – When enabled, forwards HTTP request data to CrowdSec AppSec and can escalate a request to a ban.

## Architecture

The bouncer is a single binary with three key loops:

1. `go-cs-bouncer` maintains a long-lived stream to the CrowdSec Local API and feeds new/deleted decisions into the dataset (`pkg/dataset`).
2. The SPOA worker (`pkg/spoa`) listens on TCP and/or Unix sockets, answers HAProxy messages, and applies host-specific logic such as captchas or ban pages.
3. Auxiliary services (optional) expose Prometheus metrics and pprof diagnostics.

### Request Flow (Broken Down)

This is the same end-to-end flow as the diagram below, split into the pieces you’ll actually encounter when wiring HAProxy.

#### 1) Background: decisions sync (continuous)

```mermaid
sequenceDiagram
    participant CrowdSec as CrowdSec LAPI
    participant Bouncer as go-cs-bouncer
    participant Dataset as Decision dataset

    loop Stream/poll every X seconds
        Bouncer->>CrowdSec: Fetch new/deleted decisions
        CrowdSec-->>Bouncer: Decisions delta
        Bouncer->>Dataset: Apply updates
    end
```

#### 2) Connection start: `crowdsec-ip` (always)

```mermaid
sequenceDiagram
    participant HAProxy
    participant SPOA as SPOA bouncer
    participant Dataset as Decision dataset

    HAProxy->>SPOA: crowdsec-ip (on-client-session)
    SPOA->>Dataset: Lookup source IP
    Dataset-->>SPOA: remediation (ban/allow/captcha)
    SPOA-->>HAProxy: Set txn.crowdsec.remediation
```

#### 3) HTTP request: `crowdsec-http` (per request)

```mermaid
sequenceDiagram
    participant Client
    participant HAProxy
    participant SPOA as SPOA bouncer
    participant Dataset as Decision dataset
    participant Backend

    Client->>HAProxy: HTTP request
    HAProxy->>SPOA: crowdsec-http (on-frontend-http-request)
    SPOA->>Dataset: Lookup IP + host rules
    Dataset-->>SPOA: remediation + metadata
    SPOA-->>HAProxy: remediation + isocode + captcha_status

    alt remediation = ban
        HAProxy-->>Client: 403 (ban page)
    else remediation = captcha
        HAProxy-->>Client: 200 (captcha page)
    else remediation = allow
        HAProxy->>Backend: Forward request
        Backend-->>Client: Response
    end
```

#### 4) Captcha validation (only when remediation is `captcha`)

```mermaid
sequenceDiagram
    participant Client
    participant HAProxy
    participant SPOA as SPOA bouncer

    Client->>HAProxy: Next request (includes captcha cookie)
    HAProxy->>SPOA: Validate captcha cookie
    SPOA-->>HAProxy: captcha_valid (yes/no)

    alt cookie valid
        HAProxy->>HAProxy: Treat as allow (forward upstream)
    else cookie missing/invalid
        HAProxy-->>Client: Show captcha page again
    end
```

#### 5) TCP request: `crowdsec-tcp` (per request)

```mermaid
sequenceDiagram
    participant Client
    participant HAProxy
    participant SPOA as SPOA bouncer
    participant Dataset as Decision dataset
    participant Backend

    Client->>HAProxy: TCP connection/request
    HAProxy->>SPOA: crowdsec-tcp (on-frontend-tcp-request)
    SPOA->>Dataset: Lookup source IP
    Dataset-->>SPOA: remediation (ban/allow)
    SPOA-->>HAProxy: remediation

    alt remediation = ban
        HAProxy-->>Client: Close connection
    else remediation = allow
        HAProxy->>Backend: Forward connection
        Backend-->>Client: Connected
    end
```

**Notes**
- `crowdsec-ip` runs first so every transaction carries an initial decision, even if HTTP parsing fails later.
- Host rules can override remediations (for example, force captcha on specific domains) and decide whether captcha cookies should be issued/cleared.
- Captcha sessions live in the SPOA process; HAProxy only needs to copy cookies and template variables exposed via Lua.
- AppSec validation is optional; when enabled, HTTP requests can be forwarded to CrowdSec AppSec and the result can override the remediation.

<details>
<summary>Detailed end-to-end request flow (reference)</summary>

```mermaid
sequenceDiagram
    participant Client
    participant HAProxy
    participant SPOA as SPOA Bouncer
    participant Dataset as Decision Dataset
    participant CrowdSec as CrowdSec LAPI
    participant AppSec as CrowdSec AppSec
    participant Backend

    Note over Client,HAProxy: Client Initiates Request
    Client->>HAProxy: HTTP or TCP Request
    
    Note over HAProxy,SPOA: Client Connection Established
    HAProxy->>SPOA: crowdsec-ip message<br/>(on-client-session)
    SPOA->>Dataset: Check IP remediation
    Dataset-->>SPOA: remediation (ban/allow/captcha)
    SPOA-->>HAProxy: Set txn.crowdsec.remediation
    
    alt HTTP Request
        Note over HAProxy,SPOA: HTTP Request Processing
        HAProxy->>SPOA: crowdsec-http message<br/>(on-frontend-http-request)
        SPOA->>Dataset: Check IP + Host
        Dataset-->>SPOA: IP remediation + metadata
        
        alt AppSec Enabled & (Remediation = allow/unknown || AlwaysSend = true)
            SPOA->>AppSec: Forward HTTP request data<br/>(URL, Method, Headers, Body)
            AppSec->>AppSec: Analyze request (WAF rules)
            alt AppSec Detects Threat
                AppSec-->>SPOA: Override remediation = ban
            else AppSec Allows
                AppSec-->>SPOA: Keep remediation = allow
            end
        end
        
        SPOA-->>HAProxy: Set remediation + isocode + captcha_status
        
        alt Remediation = ban
            HAProxy->>HAProxy: Render ban page (Lua)
            HAProxy-->>Client: 403 Forbidden
        else Remediation = captcha
            HAProxy->>HAProxy: Render captcha page (Lua)
            HAProxy-->>Client: 200 OK 
            alt Captcha Valid
                HAProxy->>SPOA: Validate captcha cookie
                SPOA-->>HAProxy: Set remediation = allow
                Note over HAProxy: Falls through to Remediation = allow
            else Captcha Invalid/Pending
                HAProxy-->>Client: Captcha challenge
            end
        else Remediation = allow
            HAProxy->>Backend: Forward request
            Backend-->>Client: 200 OK
        end
    else TCP Request
        Note over HAProxy,SPOA: TCP Request Processing
        HAProxy->>SPOA: crowdsec-tcp message<br/>(on-frontend-tcp-request)
        SPOA->>Dataset: Check IP remediation
        Dataset-->>SPOA: IP remediation
        SPOA-->>HAProxy: Set remediation
        
        alt Remediation = ban
            HAProxy-->>Client: Close connection
        else Remediation = allow
            HAProxy->>Backend: Forward connection
            Backend-->>Client: Connection established
        end
    end
    
    Note over SPOA,CrowdSec: Background: Stream Decisions (polled every X seconds)
    SPOA->>CrowdSec: Poll for decisions
    CrowdSec-->>SPOA: New/Deleted decisions (stream)
    SPOA->>Dataset: Update dataset (parallel batch)
```

</details>

## Install & Run

The [official documentation](https://doc.crowdsec.net/u/bouncers/haproxy_spoa) covers packaging and upgrade notes. If you want to manually build, see the build section below. A quick happy path:

1. Install the package (Debian/RPM), use the provided Docker image, or build locally with `make build`.
2. Copy [`config/crowdsec-spoa-bouncer.yaml`](config/crowdsec-spoa-bouncer.yaml) to `/etc/crowdsec/bouncers/` and set your CrowdSec LAPI URL and API key.
3. Wire the SPOE filter into HAProxy (see below) and copy the Lua helpers from [`lua/`](lua/) if you do not already ship them.
4. Start the service with `systemctl start crowdsec-haproxy-spoa-bouncer` or run `./crowdsec-spoa-bouncer -c /path/to/config.yaml` for local tests.

## Configure

Configuration is YAML. Start from the example in [`config/crowdsec-spoa-bouncer.yaml`](config/crowdsec-spoa-bouncer.yaml) and override locally with `.yaml.local`.

The bouncer supports:
- LAPI decision streaming and an in-memory dataset
- TCP and/or Unix socket listeners for HAProxy SPOE
- Optional per-host policy (ban page templating, captcha providers, logging)
- Optional GeoIP enrichment, Prometheus metrics, pprof, and AppSec validation

Detailed configuration guides:
- Hosts and match priority: [`pkg/host/README.md`](pkg/host/README.md)
- Captcha providers and configuration: [`pkg/captcha/README.md`](pkg/captcha/README.md)
- Ban page templating values: [`internal/remediation/ban/README.md`](internal/remediation/ban/README.md)

### HAProxy wiring

Add the SPOE filter and Lua helpers to your frontend. The config files in `config/` and the Lua scripts in `lua/` show complete examples; the snippet below highlights the essentials:

```haproxy
frontend www
    bind :80
    filter spoe engine crowdsec config /etc/haproxy/crowdsec.cfg

    http-request lua.crowdsec_handle if { var(txn.crowdsec.remediation) -m found }
    http-request lua.crowdsec_captcha if { var(txn.crowdsec.remediation) -m str "captcha" }
    http-request lua.crowdsec_ban if { var(txn.crowdsec.remediation) -m str "ban" }

    default_backend app
```

Use a dedicated SPOE section (`crowdsec.cfg`) to declare the messages you want HAProxy to send (`crowdsec-ip`, `crowdsec-http`, `crowdsec-tcp`) and which request variables should be exported; the provided sample covers the mandatory ones.

## Monitoring & Troubleshooting

- **Prometheus metrics** – Enable the metrics endpoint to scrape bouncer and decision counters.
- **Logging** – File or stdout logging is configurable; per-host log levels help when debugging only a subset of domains.
- **Profiling** – Switch on `pprof` in non-production environments to inspect CPU, heap, or goroutines via standard Go tooling.
- **Dataset inspection** – Use `log_level: trace` to watch BART operations and confirm that lists/ranges are loaded as expected.

## Development

Everything you need for local development is included in the repository:

```bash
git clone https://github.com/crowdsecurity/cs-haproxy-spoa-bouncer.git
cd cs-haproxy-spoa-bouncer
make build    # builds the binary in ./crowdsec-spoa-bouncer
make test     # runs Go tests
```

Docker Compose files under `docker/` and `docker-compose*.yaml` spin up HAProxy, the bouncer, and a CrowdSec LAPI for integration testing.

## Project Status & Roadmap

- AppSec validation is available for HTTP flows when configured; feedback on coverage and performance is welcome.
- Performance optimizations (batching, decision compression) continue so high-volume HAProxy tiers can rely on a single SPOA worker.

## Contributing

Contributions are welcome—feel free to open an issue or PR:
1. Fork the repo and create a topic branch (`git checkout -b feature/my-change`).
2. Run `make test` (and any relevant integration checks) before submitting.
3. Open a PR with context about the problem you solved or the feature you added.

## License

MIT – see `LICENSE` for the full text.

## Acknowledgments

- [HAProxy](https://www.haproxy.org/) for the SPOE protocol and Lua flexibility.
- [BART](https://github.com/gaissmai/bart) for the radix tree implementation that backs range lookups.
