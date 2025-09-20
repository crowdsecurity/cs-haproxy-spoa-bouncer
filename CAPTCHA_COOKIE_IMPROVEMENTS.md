# Captcha Cookie Improvements

## Overview

This implementation improves captcha cookie handling by moving cookie management from Lua to HAProxy's native `http-after-response` rules. This ensures that expired captcha cookies are properly cleared, which was previously not handled.

## Key Changes

### 1. New SPOA Fields

The SPOA bouncer now sets two new transaction variables:

- **`txn.crowdsec.captcha_status`**: Indicates the cookie action required
  - `"ok"`: Set/maintain the cookie (freshly solved captcha or valid session)
  - `"clear"`: Clear the cookie (expired or invalid session)
  - Not set: No cookie action needed

- **`txn.crowdsec.captcha_cookie`**: Contains the complete `Set-Cookie` header value
  - For `"ok"` status: Full cookie string with all attributes
  - For `"clear"` status: Cookie deletion string (MaxAge=-1)

### 2. SPOA Logic Improvements

#### Allow Remediation
- Now checks for existing captcha cookies and validates associated sessions
- Sets `captcha_status="clear"` and unset cookie when session is expired/invalid

#### Captcha Remediation
- Enhanced session validation before reusing existing cookies
- Generates new cookies only when necessary
- Sets `captcha_status="ok"` for new cookies
- Avoids unnecessary cookie operations for existing valid cookies

#### Session Validation
- Validates both cookie signature and session existence
- Properly handles session expiration (idle timeout and max time)
- Generates appropriate cookie actions based on session state

### 3. HAProxy Configuration Changes

#### New Rules
```haproxy
## Handle captcha cookie management via HAProxy (new approach)
## Set captcha cookie when SPOA indicates "ok" (freshly solved or valid session)
http-after-response set-header Set-Cookie %[var(txn.crowdsec.captcha_cookie)] if { var(txn.crowdsec.captcha_status) -m str "ok" } { var(txn.crowdsec.captcha_cookie) -m found }
## Clear captcha cookie when SPOA indicates "clear" (expired or invalid session)  
http-after-response set-header Set-Cookie %[var(txn.crowdsec.captcha_cookie)] if { var(txn.crowdsec.captcha_status) -m str "clear" } { var(txn.crowdsec.captcha_cookie) -m found }
```

#### Updated Lua Script
- Removed cookie handling from `crowdsec.lua`
- Lua now only handles page rendering (captcha/ban forms)
- Cookie management is fully delegated to HAProxy

### 4. Benefits

1. **Proper Cookie Expiration**: Expired captcha sessions now correctly clear cookies
2. **Cleaner Separation**: Cookie management separated from content rendering
3. **Better Performance**: Reduced Lua processing, native HAProxy cookie handling
4. **Consistent Behavior**: HAProxy handles all cookie operations uniformly
5. **Easier Debugging**: Cookie operations visible in HAProxy logs

## Implementation Details

### Session Expiration Detection

The implementation detects expired sessions in multiple scenarios:

1. **Cookie Validation Failure**: Invalid signature or format
2. **Session Not Found**: UUID exists but session was garbage collected
3. **Idle Timeout**: Session inactive beyond `SessionIdleTimeout` (default: 1h)
4. **Max Time Reached**: Session older than `SessionMaxTime` (default: 12h)

### Cookie Generation

- **New Cookies**: Generated with appropriate security flags (Secure, HttpOnly, SameSite)
- **Clear Cookies**: Generated with `MaxAge=-1` to instruct browser deletion
- **Full Headers**: Complete `Set-Cookie` header values include all necessary attributes

### Backward Compatibility

- Existing captcha page templates remain unchanged
- Ban remediation logic unchanged
- Session management core functionality preserved
- Configuration changes are additive (old configs work with minor updates)

## Testing Scenarios

1. **Fresh Captcha**: New user should get cookie with `captcha_status="ok"`
2. **Valid Session**: Returning user with valid session should maintain cookie
3. **Expired Session**: User with expired session should get `captcha_status="clear"`
4. **Invalid Cookie**: Malformed cookie should trigger `captcha_status="clear"`
5. **Successful Validation**: Completed captcha should maintain cookie with `captcha_status="ok"`

## Configuration Examples

### Minimal HAProxy Frontend
```haproxy
frontend web
    mode http
    bind *:80
    
    filter spoe engine crowdsec config /etc/haproxy/crowdsec.cfg
    
    # Standard request processing
    http-request lua.crowdsec_handle if { var(txn.crowdsec.remediation) -m found }
    
    # New cookie management rules
    http-after-response set-header Set-Cookie %[var(txn.crowdsec.captcha_cookie)] if { var(txn.crowdsec.captcha_status) -m str "ok" } { var(txn.crowdsec.captcha_cookie) -m found }
    http-after-response set-header Set-Cookie %[var(txn.crowdsec.captcha_cookie)] if { var(txn.crowdsec.captcha_status) -m str "clear" } { var(txn.crowdsec.captcha_cookie) -m found }
    
    default_backend web_servers
```

### Session Configuration
```yaml
hosts:
  - host: "example.com"
    captcha:
      provider: "hcaptcha"
      site_key: "your-site-key"
      secret_key: "your-secret-key"
      # Session settings affect cookie expiration
      session_idle_timeout: "1h"    # Clear cookie after 1h inactivity
      session_max_time: "12h"       # Clear cookie after 12h total
      cookie:
        secure: "auto"              # Secure flag based on SSL
        http_only: true             # HttpOnly for security
        sign_cookies: true          # Sign cookies for integrity
```

## Migration Guide

1. **Update HAProxy Config**: Add the new `http-after-response` rules
2. **Deploy SPOA**: Update to version with new captcha_status/captcha_cookie fields
3. **Test Cookie Behavior**: Verify cookies are set/cleared properly
4. **Monitor Logs**: Check for proper cookie operations in HAProxy logs

The changes are designed to be backward compatible, but the new cookie management rules must be added to take advantage of the improvements.
