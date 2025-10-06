#!/bin/sh

set -eu

. ./scripts/_bouncer.sh

# Parse command line arguments
FORCE_UPGRADE=false
while [ $# -gt 0 ]; do
    case "$1" in
        --force|-f)
            FORCE_UPGRADE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--force|-f] [--help|-h]"
            echo "  --force, -f    Force upgrade even if versions are the same"
            echo "  --help, -h     Show this help message"
            exit 0
            ;;
        *)
            msg err "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

assert_root

# --------------------------------- #

# Check if upgrade is needed (unless forced)
if [ "$FORCE_UPGRADE" = "false" ]; then
    if ! check_upgrade_needed; then
        msg info "No upgrade needed or upgrade not recommended"
        msg info "Use --force to override this check"
        exit 0
    fi
else
    msg info "Force upgrade enabled, skipping version check"
    # Still show version info for user awareness
    current_version=$(get_bouncer_version "$BIN_PATH_INSTALLED")
    new_version=$(get_bouncer_version "$BIN_PATH")
    msg info "Current version: $current_version"
    msg info "New version: $new_version"
fi

# Ask for confirmation if running interactively
if [ -t 0 ]; then
    echo
    msg info "Do you want to proceed with the upgrade? (y/N)"
    read -r response
    case "$response" in
        [yY]|[yY][eE][sS])
            msg info "Proceeding with upgrade..."
            ;;
        *)
            msg info "Upgrade cancelled by user"
            exit 0
            ;;
    esac
fi

systemctl stop "$SERVICE"

if ! upgrade_bin; then
    msg err "failed to upgrade $BOUNCER"
    exit 1
fi

systemctl start "$SERVICE" || msg warn "$SERVICE failed to start, please check the systemd logs"

msg succ "$BOUNCER upgraded successfully."
exit 0
