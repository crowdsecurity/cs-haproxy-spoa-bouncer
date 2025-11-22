#!/bin/sh
#shellcheck disable=SC3043

set -eu

BOUNCER="crowdsec-spoa-bouncer"
BOUNCER_PREFIX=$(echo "$BOUNCER" | sed 's/crowdsec-/cs-/g')

# This is a library of functions that can be sourced by other scripts
# to install and configure bouncers.
#
# While not requiring bash, it is not strictly POSIX-compliant because
# it uses local variables, but it should work with every modern shell.
#
# Since passing/parsing arguments in posix sh is tricky, we share
# some environment variables with the functions. It's a matter of
# readability balance between shorter vs cleaner code.

if [ -n "${NO_COLOR-}" ] || [ ! -t 1 ]; then
    # terminal is not interactive; no colors
    FG_RED=""
    FG_GREEN=""
    FG_YELLOW=""
    FG_CYAN=""
    RESET=""
elif [ -n "${TERM-}" ] && tput sgr0 >/dev/null 2>&1; then
    # terminfo
    FG_RED=$(tput setaf 1)
    FG_GREEN=$(tput setaf 2)
    FG_YELLOW=$(tput setaf 3)
    FG_CYAN=$(tput setaf 6)
    RESET=$(tput sgr0)
else
    FG_RED=$(printf '%b' '\033[31m')
    FG_GREEN=$(printf '%b' '\033[32m')
    FG_YELLOW=$(printf '%b' '\033[33m')
    FG_CYAN=$(printf '%b' '\033[36m')
    RESET=$(printf '%b' '\033[0m')
fi

msg() {
    case "$1" in
    info) echo "${FG_CYAN}$2${RESET}" >&2 ;;
    warn) echo "${FG_YELLOW}WARN:${RESET} $2" >&2 ;;
    err) echo "${FG_RED}ERR:${RESET} $2" >&2 ;;
    succ) echo "${FG_GREEN}$2${RESET}" >&2 ;;
    *) echo "$1" >&2 ;;
    esac
}

require() {
    set | grep -q "^$1=" || {
        msg err "missing required variable \$$1"
        exit 1
    }
    shift
    [ "$#" -eq 0 ] || require "$@"
}

# shellcheck disable=SC2034
{
    SERVICE="$BOUNCER.service"
    BIN_PATH_INSTALLED="/usr/bin/$BOUNCER"
    BIN_PATH="./$BOUNCER"
    CONFIG_DIR="/etc/crowdsec/bouncers"
    CONFIG_FILE="$BOUNCER.yaml"
    CONFIG="$CONFIG_DIR/$CONFIG_FILE"
    SYSTEMD_PATH_FILE="/etc/systemd/system/$SERVICE"
}

assert_root() {
    #shellcheck disable=SC2312
    if [ "$(id -u)" -ne 0 ]; then
        msg err "This script must be run as root"
        exit 1
    fi
}

# Check if the configuration file contains a variable
# which has not yet been interpolated, like "$API_KEY",
# and return true if it does.
config_not_set() {
    require 'CONFIG'
    local varname before after

    varname=$1
    if [ "$varname" = "" ]; then
        msg err "missing required variable name"
        exit 1
    fi

    before=$("$BOUNCER" -c "$CONFIG" -T)
    # shellcheck disable=SC2016
    after=$(echo "$before" | envsubst "\$$varname")

    if [ "$before" = "$after" ]; then
        return 1
    fi
    return 0
}

need_api_key() {
    if config_not_set 'API_KEY'; then
        return 0
    fi
    return 1
}

# Interpolate a variable in the config file with a value.
set_config_var_value() {
    require 'CONFIG'
    local varname value before

    varname=$1
    if [ "$varname" = "" ]; then
        msg err "missing required variable name"
        exit 1
    fi

    value=$2
    if [ "$value" = "" ]; then
        msg err "missing required variable value"
        exit 1
    fi

    before=$(cat "$CONFIG")
    (umask 177 && echo "$before" | \
        env "$varname=$value" envsubst "\$$varname" >"$CONFIG")
}

set_api_key() {
    require 'CONFIG' 'BOUNCER_PREFIX'
    local api_key ret bouncer_id before
    # if we can't set the key, the user will take care of it
    ret=0

    if command -v cscli >/dev/null; then
        echo "cscli/crowdsec is present, generating API key" >&2
        bouncer_id="$BOUNCER_PREFIX-$(date +%s)"
        api_key=$(cscli -oraw bouncers add "$bouncer_id" || true)
        if [ "$api_key" = "" ]; then
            echo "failed to create API key" >&2
            api_key="<API_KEY>"
            ret=1
        else
            echo "API Key successfully created" >&2
            echo "$bouncer_id" >"$CONFIG.id"
        fi
    else
        echo "cscli/crowdsec is not present, please set the API key manually" >&2
        api_key="<API_KEY>"
        ret=1
    fi

    if [ "$api_key" != "" ]; then
        set_config_var_value 'API_KEY' "$api_key"
    fi

    return "$ret"
}

set_local_port() {
    require 'CONFIG'
    local port
    command -v cscli >/dev/null || return 0
    # the following will fail with a non-LAPI local crowdsec, leaving empty port
    port=$(cscli config show -oraw --key "Config.API.Server.ListenURI" 2>/dev/null | cut -d ":" -f2 || true)
    if [ "$port" != "" ]; then
        sed -i "s/localhost:8080/127.0.0.1:$port/g" "$CONFIG"
        sed -i "s/127.0.0.1:8080/127.0.0.1:$port/g" "$CONFIG"
    fi
}

set_local_lapi_url() {
    require 'CONFIG'
    local port before varname
    # $varname is the name of the variable to interpolate
    # in the config file with the URL of the LAPI server,
    # assuming it is running on the same host as the
    # bouncer.
    varname=$1
    if [ "$varname" = "" ]; then
        msg err "missing required variable name"
        exit 1
    fi
    command -v cscli >/dev/null || return 0

    port=$(cscli config show -oraw --key "Config.API.Server.ListenURI" 2>/dev/null | cut -d ":" -f2 || true)
    if [ "$port" = "" ]; then
        port=8080
    fi

    set_config_var_value "$varname" "http://127.0.0.1:$port"
}

delete_bouncer() {
    require 'CONFIG'
    local bouncer_id
    if [ -f "$CONFIG.id" ]; then
        bouncer_id=$(cat "$CONFIG.id")
        cscli -oraw bouncers delete "$bouncer_id" 2>/dev/null || true
        rm -f "$CONFIG.id"
    fi
}

# Extract version from bouncer binary output
get_bouncer_version() {
    local bouncer_bin version_output
    bouncer_bin="$1"
    
    if [ ! -f "$bouncer_bin" ]; then
        echo "0.0.0"
        return 1
    fi
    
    version_output=$("$bouncer_bin" --version 2>&1 || echo "")
    if [ "$version_output" = "" ]; then
        echo "0.0.0"
        return 1
    fi
    
    # Extract version from output like "version: v1.2.3-abc123..."
    echo "$version_output" | grep -Eio 'v[0-9]+.[0-9]+.[0-9]+' | cut -c 2- || echo "0.0.0"
}

# Compare two version strings (returns 0 if v1 >= v2, 1 otherwise)
version_compare() {
    local v1 v2
    v1="$1"
    v2="$2"
    
    # Split versions into major.minor.patch
    local v1_major v1_minor v1_patch v2_major v2_minor v2_patch
    
    v1_major=$(echo "$v1" | cut -d'.' -f1)
    v1_minor=$(echo "$v1" | cut -d'.' -f2)
    v1_patch=$(echo "$v1" | cut -d'.' -f3)
    
    v2_major=$(echo "$v2" | cut -d'.' -f1)
    v2_minor=$(echo "$v2" | cut -d'.' -f2)
    v2_patch=$(echo "$v2" | cut -d'.' -f3)
    
    # Compare major version
    if [ "$v1_major" -gt "$v2_major" ]; then
        return 0
    elif [ "$v1_major" -lt "$v2_major" ]; then
        return 1
    fi
    
    # Compare minor version
    if [ "$v1_minor" -gt "$v2_minor" ]; then
        return 0
    elif [ "$v1_minor" -lt "$v2_minor" ]; then
        return 1
    fi
    
    # Compare patch version
    if [ "$v1_patch" -ge "$v2_patch" ]; then
        return 0
    else
        return 1
    fi
}

# Check if upgrade is needed by comparing versions
check_upgrade_needed() {
    local current_version new_version
    current_version=$(get_bouncer_version "$BIN_PATH_INSTALLED")
    new_version=$(get_bouncer_version "$BIN_PATH")
    
    msg info "Current version: $current_version"
    msg info "New version: $new_version"
    
    if version_compare "$new_version" "$current_version"; then
        if [ "$new_version" = "$current_version" ]; then
            msg info "Versions are the same, no upgrade needed"
            return 1
        else
            msg info "Upgrade available: $current_version -> $new_version"
            return 0
        fi
    else
        msg warn "New version ($new_version) is older than current version ($current_version)"
        return 1
    fi
}

upgrade_bin() {
    require 'BIN_PATH' 'BIN_PATH_INSTALLED'
    rm "$BIN_PATH_INSTALLED"
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
}
