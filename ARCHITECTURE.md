# Architecture

This document describes how the bouncer works under the hood and how HAProxy interacts with it via SPOE.

## Components

The bouncer is a single binary with three key loops:

1. `go-cs-bouncer` maintains a long-lived stream to the CrowdSec Local API and feeds new/deleted decisions into the dataset (`pkg/dataset`).
2. The SPOA worker (`pkg/spoa`) listens on TCP and/or Unix sockets, answers HAProxy messages, and applies host-specific logic such as captchas or ban pages.
3. Auxiliary services (optional) expose Prometheus metrics and pprof diagnostics.

## Request Flow (Detailed)

These diagrams focus on what you configure and observe in HAProxy: when SPOE messages are sent, what the bouncer returns, and where HAProxy takes action (render a page, set cookies, forward upstream).

**Legend**
- **SPOE message**: a request from HAProxy to the SPOA bouncer (for example `crowdsec-tcp` or `crowdsec-http-body`).
- **SPOE group**: what HAProxy sends from the frontend via `http-request send-spoe-group ...`; a group can contain one or more SPOE messages.
- **Remediation**: the decision HAProxy enforces (`allow`, `captcha`, `ban`).
- **Transaction variables**: values the bouncer sets on the HAProxy transaction (for example `txn.crowdsec.remediation`) for ACLs, headers, Lua templates, redirects, and cookie management.

### 1) Background: decisions sync (continuous)

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

### 2) Connection start: `crowdsec-tcp` (always)

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

### 3) HTTP request: `crowdsec-http-body` / `crowdsec-http-no-body` (per request)

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

### 4) Captcha lifecycle (challenge → submit → cookie → redirect)

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

### 5) TCP enforcement: `crowdsec-tcp` (session-level)

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

## Full End-to-End Sequence (Reference)

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

## Examples

For complete, working examples (including request-body forwarding, captcha redirects, and cookie management), see:
- `config/haproxy.cfg`
- `config/crowdsec.cfg`

