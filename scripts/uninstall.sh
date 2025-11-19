#!/bin/bash

set -eu

. ./scripts/_bouncer.sh

assert_root

# --------------------------------- #

uninstall() {
    systemctl stop "$SERVICE" || true
    delete_bouncer
    rm -f "$CONFIG"
    rm -f "$SYSTEMD_PATH_FILE"
    rm -f "$BIN_PATH_INSTALLED"
    # Clean up log files
    rm -f "/var/log/$BOUNCER.log"*  # Legacy location
    rm -rf "/var/log/crowdsec-spoa"  # New location
    systemctl daemon-reload || true
}

uninstall
msg succ "$BOUNCER has been successfully uninstalled"
exit 0
