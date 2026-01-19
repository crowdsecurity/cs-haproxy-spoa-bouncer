<div align="center">
  <img src="img/crowdsec_haproxy.svg" alt="CrowdSec HAProxy" width="400"/>
</div>

# CrowdSec HAProxy SPOA Bouncer

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A lightweight Stream Processing Offload Agent (SPOA) that contacts the CrowdSec Local API to fetch decisions in real time while aiming to be highly performant and minimize latency for clients. It manages an in-memory cache of bans and captchas, and directs HAProxy on how to treat each connection without blocking the data path.

## At a Glance

- **Real-time enforcement** – Streams decisions from CrowdSec via the Go bouncer SDK so ban/captcha/allow changes are visible within seconds.
- **HTTP and TCP coverage** – Supports early IP checks via `crowdsec-tcp` and HTTP inspection via `crowdsec-http-body` / `crowdsec-http-no-body` to protect both web frontends and raw TCP services.
- **Host-aware responses** – Each host entry can customize ban pages, captcha providers, and logging while sharing the same SPOA worker.
- **Captcha challenges built in** – hCaptcha, reCAPTCHA, and Cloudflare Turnstile are supported with signed, stateless cookies so solved challenges can be verified without round-tripping to the provider.
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

These diagrams focus on what you configure and observe in HAProxy: when SPOE messages are sent, what the bouncer returns, and where HAProxy takes action (render a page, set cookies, forward upstream).

**Legend**
- **SPOE message**: a request from HAProxy to the SPOA bouncer (for example `crowdsec-tcp` or `crowdsec-http-body`).
- **SPOE group**: what HAProxy actually sends from the frontend via `http-request send-spoe-group ...`; a group can contain one or more SPOE messages.
- **Remediation**: the decision HAProxy enforces (`allow`, `captcha`, `ban`).
- **Transaction variables**: values the bouncer sets on the HAProxy transaction (for example `txn.crowdsec.remediation`) for ACLs, headers, Lua templates, redirects, and cookie management.

#### Overview (one page)

```mermaid
flowchart LR
  subgraph Background["Background (continuous)"]
    CrowdSec["CrowdSec LAPI"] -->|"decision stream"| Bouncer["go-cs-bouncer"]
    Bouncer -->|"updates"| Dataset[("Decision dataset")]
  end

  subgraph DataPath["Request path (per connection / request)"]
    Client["Client"] --> HAProxy["HAProxy"]
    HAProxy -->|"SPOE: crowdsec-tcp (session)"| SPOA["SPOA bouncer"]
    HAProxy -->|"SPOE group: crowdsec-http-body"| SPOA
    HAProxy -->|"SPOE group: crowdsec-http-no-body"| SPOA
    SPOA --> Dataset
    SPOA -->|"txn vars (remediation + metadata)"| HAProxy
    HAProxy -->|"allow"| Backend["Backend"]
    HAProxy -->|"captcha / ban"| Lua["Lua templates"]
    Lua --> Client
  end
```

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

#### 2) Connection start: `crowdsec-tcp` (always)

```mermaid
sequenceDiagram
    participant HAProxy
    participant SPOA as SPOA bouncer
    participant Dataset as Decision dataset

    Note over HAProxy,SPOA: Runs once per client session/connection
    HAProxy->>SPOA: crowdsec-tcp (source IP)
    SPOA->>Dataset: Lookup source IP
    Dataset-->>SPOA: remediation (ban/allow/captcha)
    SPOA-->>HAProxy: Set txn vars (remediation baseline)
```

#### 3) HTTP request: `crowdsec-http-body` / `crowdsec-http-no-body` (per request)

```mermaid
sequenceDiagram
    participant Client
    participant HAProxy
    participant SPOA as SPOA bouncer
    participant Policy as Host policy
    participant Dataset as Decision dataset
    participant AppSec as CrowdSec AppSec (optional)
    participant Backend

    Client->>HAProxy: HTTP request
    alt Body within limit
        HAProxy->>SPOA: SPOE group crowdsec-http-body<br/>(host + method + headers + body)
    else Body too large / not needed
        HAProxy->>SPOA: SPOE group crowdsec-http-no-body<br/>(host + method + headers)
    end
    Note over HAProxy,SPOA: Captcha form submissions must use crowdsec-http-body<br/>(validation needs the request body)
    SPOA->>Policy: Match host rules (Host header / SNI)
    Policy-->>SPOA: ban/captcha settings + AppSec toggles
    SPOA->>Dataset: Lookup source IP / CIDR / country
    Dataset-->>SPOA: remediation baseline + metadata

    opt AppSec enabled (host or global)
        SPOA->>AppSec: Validate HTTP request (method/uri/headers/body)
        AppSec-->>SPOA: allow or ban
    end

    SPOA-->>HAProxy: Set txn vars (remediation + metadata + captcha vars)

    alt remediation = ban
        HAProxy-->>Client: 403 (rendered by Lua)
    else remediation = captcha
        HAProxy-->>Client: 200 (captcha page rendered by Lua)
    else remediation = allow
        HAProxy->>Backend: Forward request
        Backend-->>Client: Response
    end
```

#### 4) Captcha lifecycle (challenge → submit → cookie → redirect)

```mermaid
sequenceDiagram
    participant Client
    participant HAProxy
    participant SPOA as SPOA bouncer
    participant Provider as Captcha provider
    participant Backend

    Note over Client,HAProxy: Request triggers captcha remediation
    Client->>HAProxy: HTTP request
    HAProxy->>SPOA: SPOE group crowdsec-http-no-body (GET)
    SPOA-->>HAProxy: txn vars (remediation=captcha, captcha params, captcha cookie pending)
    HAProxy-->>Client: 200 captcha page (Lua)

    Note over Client,HAProxy: User solves captcha and submits the form
    Client->>HAProxy: POST captcha submission (form-encoded)
    HAProxy->>SPOA: SPOE group crowdsec-http-body (POST + body)
    Note over HAProxy,SPOA: Body forwarding is required for captcha validation
    SPOA->>Provider: Verify captcha response
    Provider-->>SPOA: valid/invalid

    alt captcha valid
        SPOA-->>HAProxy: remediation=allow + redirect=1 + updated captcha cookie
        HAProxy-->>Client: 302 redirect + Set-Cookie
        Client->>HAProxy: Follow redirect (includes captcha cookie)
        HAProxy->>SPOA: SPOE group crowdsec-http-no-body (GET)
        SPOA-->>HAProxy: remediation=allow (cookie validated)
        HAProxy->>Backend: Forward request
        Backend-->>Client: Response
    else captcha invalid/missing
        SPOA-->>HAProxy: remediation=captcha (still pending)
        HAProxy-->>Client: 200 captcha page (Lua)
    end
```

#### 5) TCP enforcement: `crowdsec-tcp` (session-level)

```mermaid
sequenceDiagram
    participant Client
    participant HAProxy
    participant SPOA as SPOA bouncer
    participant Dataset as Decision dataset
    participant Backend

    Client->>HAProxy: TCP connection
    HAProxy->>SPOA: crowdsec-tcp (on-client-session)
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
- `crowdsec-tcp` runs first so every connection carries an initial decision, even if HTTP parsing fails later.
- Host rules can override remediations (for example, force captcha on specific domains) and decide whether captcha cookies should be issued/cleared.
- Captcha state is stateless and carried in a signed token cookie; HAProxy can set/clear it using transaction variables, while Lua focuses on rendering pages.
- Captcha validation requires the form body; ensure captcha POSTs are sent via the `crowdsec-http-body` SPOE group.
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
    HAProxy->>SPOA: crowdsec-tcp message<br/>(on-client-session)
    SPOA->>Dataset: Check IP remediation
    Dataset-->>SPOA: remediation (ban/allow/captcha)
    SPOA-->>HAProxy: Set txn.crowdsec.remediation
    
    alt HTTP Request
        Note over HAProxy,SPOA: HTTP Request Processing
        alt Body within limit
            HAProxy->>SPOA: SPOE group crowdsec-http-body<br/>(message crowdsec-http-body, includes body)
        else Body too large / not needed
            HAProxy->>SPOA: SPOE group crowdsec-http-no-body<br/>(message crowdsec-http-no-body)
        end
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
        
        SPOA-->>HAProxy: Set txn vars (remediation + metadata + captcha vars)
        
        alt Remediation = ban
            HAProxy->>HAProxy: Render ban page (Lua)
            HAProxy-->>Client: 403 Forbidden
        else Remediation = captcha
            HAProxy->>HAProxy: Render captcha page (Lua)
            HAProxy-->>Client: 200 OK

            Note over Client,HAProxy: Client submits captcha solution (POST)
            Client->>HAProxy: Captcha form submission
            HAProxy->>SPOA: SPOE group crowdsec-http-body<br/>(message crowdsec-http-body, includes body)
            SPOA-->>HAProxy: remediation allow/captcha + redirect/cookie vars

            alt Captcha Valid
                HAProxy-->>Client: 302 redirect + Set-Cookie
            else Captcha Invalid/Pending
                HAProxy-->>Client: 200 OK (captcha page)
            end
        else Remediation = allow
            HAProxy->>Backend: Forward request
            Backend-->>Client: 200 OK
        end
    else TCP Request
        Note over HAProxy: TCP uses the session decision from crowdsec-tcp
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

    http-request lua.crowdsec_handle if { var(txn.crowdsec.remediation) -m str "captcha" }
    http-request lua.crowdsec_handle if { var(txn.crowdsec.remediation) -m str "ban" }

    default_backend app
```

Use a dedicated SPOE section (`crowdsec.cfg`) to declare the messages HAProxy sends and which request variables are exported. The provided sample uses:
- `crowdsec-tcp` (event `on-client-session`) for early, connection-level IP decisions
- `crowdsec-http-body` / `crowdsec-http-no-body` (sent via SPOE groups with the same names) for per-request HTTP inspection, with optional body forwarding

Important: captcha validation needs the request body (form-encoded POST). Ensure your frontend sends captcha submissions via the `crowdsec-http-body` group (see `http-request send-spoe-group ... crowdsec-http-body` in the examples).

For complete, working examples (including optional request-body forwarding, captcha redirects, and cookie management), see [`config/haproxy.cfg`](config/haproxy.cfg) and [`config/crowdsec.cfg`](config/crowdsec.cfg).

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
