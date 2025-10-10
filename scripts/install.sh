#!/bin/sh

set -eu

. ./scripts/_bouncer.sh

assert_root

# --------------------------------- #

API_KEY="<API_KEY>"

gen_apikey() {
    if command -v cscli >/dev/null; then
        msg succ "cscli found, generating bouncer api key."
        bouncer_id="$BOUNCER_PREFIX-$(date +%s)"
        API_KEY=$(cscli -oraw bouncers add "$bouncer_id")
        echo "$bouncer_id" > "$CONFIG.id"
        msg info "API Key: $API_KEY"
        READY="yes"
    else
        msg warn "cscli not found, you will need to generate an api key."
        READY="no"
    fi
}

gen_config_file() {
    # shellcheck disable=SC2016
    API_KEY=${API_KEY} envsubst '$API_KEY' <"./config/$CONFIG_FILE" | \
        install -D -m 0640 -g crowdsec-spoa /dev/stdin "$CONFIG"
}

install_bouncer() {
    if [ ! -f "$BIN_PATH" ]; then
        msg err "$BIN_PATH not found, exiting."
        exit 1
    fi
    if [ -e "$BIN_PATH_INSTALLED" ]; then
        msg err "$BIN_PATH_INSTALLED is already installed. Exiting"
        exit 1
    fi
    
    # Ensure crowdsec-spoa group exists
    if ! getent group crowdsec-spoa >/dev/null 2>&1; then
        msg info "Creating crowdsec-spoa group"
        groupadd --system crowdsec-spoa || addgroup --system crowdsec-spoa
    fi
    
    # Ensure crowdsec-spoa user exists
    if ! getent passwd crowdsec-spoa >/dev/null 2>&1; then
        msg info "Creating crowdsec-spoa user"
        useradd --system --no-create-home --shell /sbin/nologin -g crowdsec-spoa crowdsec-spoa 2>/dev/null || \
            adduser --system --no-create-home --shell /sbin/nologin --ingroup crowdsec-spoa crowdsec-spoa
    fi
    
    msg info "Installing $BOUNCER"
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
    install -D -m 0640 -g crowdsec-spoa "./config/$CONFIG_FILE" "$CONFIG"
    # shellcheck disable=SC2016
    CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst '$CFG $BIN' <"./config/$SERVICE" >"$SYSTEMD_PATH_FILE"
    # Install optional admin socket unit (disabled by default)
    if [ -f "./config/$ADMIN_SOCKET" ]; then
        msg info "Installing optional admin socket unit (disabled by default)"
        install -D -m 0644 "./config/$ADMIN_SOCKET" "$SYSTEMD_ADMIN_SOCKET_FILE"
    fi
    systemctl daemon-reload
    gen_apikey
    gen_config_file
}

# --------------------------------- #

install_bouncer

echo ""
echo "=========================================="
echo "CrowdSec HAProxy SPOA Bouncer installed"
echo "=========================================="
echo ""

if [ "$READY" = "no" ]; then
    msg warn "No API key was generated."
    echo "  Generate one with: cscli bouncers add <bouncer_name>"
    echo "  Add it to: $CONFIG"
    echo ""
fi

echo "Configuration: $CONFIG"
echo "Example configs: /usr/share/crowdsec/config/ (or ./config/ in source)"
echo "Documentation: https://docs.crowdsec.net/u/bouncers/haproxy_spoa/"
echo ""
echo "Start bouncer: systemctl enable --now $SERVICE"
echo ""
echo "Optional admin socket (disabled by default):"
echo "  Enable: systemctl enable --now $ADMIN_SOCKET"
echo "  Uncomment 'admin_socket' in $CONFIG"
echo "  Restart: systemctl restart $SERVICE"
exit 0
