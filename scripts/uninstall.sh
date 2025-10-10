#!/bin/bash

set -eu

. ./scripts/_bouncer.sh

assert_root

# --------------------------------- #

uninstall() {
    systemctl stop "$SERVICE" || true
    # Stop and disable admin socket if enabled
    systemctl stop "$ADMIN_SOCKET" || true
    systemctl disable "$ADMIN_SOCKET" || true
    delete_bouncer
    rm -f "$CONFIG"
    rm -f "$SYSTEMD_PATH_FILE"
    rm -f "$SYSTEMD_ADMIN_SOCKET_FILE"
    rm -f "$BIN_PATH_INSTALLED"
    rm -f "/var/log/$BOUNCER.log"
    systemctl daemon-reload || true
}

uninstall
msg succ "$BOUNCER has been successfully uninstalled"
exit 0
