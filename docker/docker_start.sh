#!/bin/sh

export CONFIG_FILE="${CONFIG_FILE:=/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml}"

# Ensure runtime directory exists (no systemd in container)
mkdir -p /run/crowdsec-spoa
chmod 750 /run/crowdsec-spoa

ARGS=""
if [ "$CONFIG_FILE" != "" ]; then
    ARGS="-c $CONFIG_FILE"
fi

# shellcheck disable=SC2086
exec /usr/local/bin/crowdsec-spoa-bouncer $ARGS
