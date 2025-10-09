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
        install -D -m 0600 /dev/stdin "$CONFIG"
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
    msg info "Installing $BOUNCER"
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
    install -D -m 0600 "./config/$CONFIG_FILE" "$CONFIG"
    # shellcheck disable=SC2016
    CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst '$CFG $BIN' <"./config/$SERVICE" >"$SYSTEMD_PATH_FILE"
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
echo "Documentation: https://docs.crowdsec.net/u/bouncers/haproxy_spoa"
echo ""
echo "Start bouncer: systemctl enable --now $SERVICE"
exit 0
