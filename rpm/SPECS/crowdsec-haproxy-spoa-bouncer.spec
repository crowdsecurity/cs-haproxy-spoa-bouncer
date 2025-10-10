Name:      crowdsec-haproxy-spoa-bouncer
Version:   %(echo $VERSION)
Release:   %(echo $PACKAGE_NUMBER)%{?dist}
Summary:   Haproxy bouncer for Crowdsec

License:   MIT
URL:       https://crowdsec.net
Source0:   https://github.com/crowdsecurity/%{name}/archive/v%(echo $VERSION).tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: make
%{?fc33:BuildRequires: systemd-rpm-macros}

Requires: gettext

%define debug_package %{nil}

%description

%define version_number %(echo $VERSION)
%define releasever %(echo $RELEASEVER)
%global local_version v%{version_number}-%{releasever}-rpm
%global name crowdsec-haproxy-spoa-bouncer
%global __mangle_shebangs_exclude_from /usr/bin/env
%define binary_name crowdsec-spoa-bouncer

%prep
%setup -n %{name}-%{version}

%build
BUILD_VERSION=%{local_version} make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libdir}/%{name}
mkdir -p %{buildroot}%{_localstatedir}/lib/%{name}/html
mkdir -p %{buildroot}%{_docdir}/examples
install -m 755 -D %{binary_name} %{buildroot}%{_bindir}/%{binary_name}
install -m 640 -D config/%{binary_name}.yaml %{buildroot}/etc/crowdsec/bouncers/%{binary_name}.yaml
install -m 640 -D scripts/_bouncer.sh %{buildroot}/usr/lib/%{name}/_bouncer.sh
install -m 644 -D config/crowdsec.cfg %{buildroot}/%{_docdir}/%{name}/examples/crowdsec.cfg
install -m 644 -D config/haproxy.cfg %{buildroot}/%{_docdir}/%{name}/examples/haproxy.cfg
BIN=%{_bindir}/%{binary_name} CFG=/etc/crowdsec/bouncers envsubst '$BIN $CFG' < config/%{binary_name}.service | install -m 0644 -D /dev/stdin %{buildroot}%{_unitdir}/%{binary_name}.service
install -m 0644 -D config/%{binary_name}-admin.socket %{buildroot}%{_unitdir}/%{binary_name}-admin.socket
install -D lua/crowdsec.lua %{buildroot}/usr/lib/%{name}/lua/crowdsec.lua
install -D lua/utils.lua %{buildroot}/usr/lib/%{name}/lua/utils.lua
install -D lua/template.lua %{buildroot}/usr/lib/%{name}/lua/template.lua
install -D templates/ban.html %{buildroot}%{_localstatedir}/lib/%{name}/html/ban.html
install -D templates/captcha.html %{buildroot}%{_localstatedir}/lib/%{name}/html/captcha.html

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/%{binary_name}
/usr/lib/%{name}/_bouncer.sh
%{_unitdir}/%{binary_name}.service
%{_unitdir}/%{binary_name}-admin.socket
%config(noreplace) /etc/crowdsec/bouncers/%{binary_name}.yaml
%doc %{_docdir}/%{name}/examples/crowdsec.cfg
%doc %{_docdir}/%{name}/examples/haproxy.cfg
/usr/lib/%{name}/lua/crowdsec.lua
/usr/lib/%{name}/lua/utils.lua
/usr/lib/%{name}/lua/template.lua
%{_localstatedir}/lib/%{name}/html/ban.html
%{_localstatedir}/lib/%{name}/html/captcha.html

%post
# Reload systemd units
systemctl daemon-reexec >/dev/null 2>&1 || :
systemctl daemon-reload >/dev/null 2>&1 || :

# Set binary and service variables
BINARY_NAME="crowdsec-spoa-bouncer"
NAME="crowdsec-haproxy-spoa-bouncer"
SERVICE="${BINARY_NAME}.service"
CONFIG="/etc/crowdsec/bouncers/${BINARY_NAME}.yaml"
START=1

# Source helper script
if [ -f "/usr/lib/${NAME}/_bouncer.sh" ]; then
    . "/usr/lib/${NAME}/_bouncer.sh"
else
    echo "Missing _bouncer.sh, cannot auto-generate API key." >&2
    START=0
fi

# On fresh install (not upgrade), try to generate API key
if [ "$1" = "1" ]; then
    if need_api_key; then
        if ! set_api_key; then
            START=0
        fi
    fi
fi

# Ensure system user and group exist
if ! getent group crowdsec-spoa >/dev/null; then
    groupadd --system crowdsec-spoa
fi

if ! getent passwd crowdsec-spoa >/dev/null; then
    adduser --system --no-create-home --shell /sbin/nologin -g crowdsec-spoa crowdsec-spoa
fi

# Set config file group ownership
chgrp crowdsec-spoa "$CONFIG" 2>/dev/null || true


if [ -d "/etc/haproxy" ]; then
    cp /usr/share/doc/%{name}/examples/crowdsec.cfg /etc/haproxy/crowdsec.cfg
fi

# Display installation message
echo ""
echo "=========================================="
echo "CrowdSec HAProxy SPOA Bouncer installed"
echo "=========================================="
echo ""

if [ "$START" -eq 0 ]; then
    echo "⚠ No API key was generated."
    echo "  Generate one with: cscli bouncers add <bouncer_name>"
    echo "  Add it to: $CONFIG"
    echo ""
fi

echo "Configuration: $CONFIG"
echo "Examples: /usr/share/doc/%{name}/examples/"
echo "Documentation: https://docs.crowdsec.net/u/bouncers/haproxy_spoa"
echo ""
echo "Start bouncer: systemctl enable --now $SERVICE"

%changelog
* Fri Jun 13 2025 Manuel Sabban <manuel@crowdsec.net>
- First initial packaging

%preun
. /usr/lib/%{name}/_bouncer.sh

if [ "$1" = "0" ]; then
    systemctl stop "$SERVICE" || echo "cannot stop service"
    systemctl disable "$SERVICE" || echo "cannot disable service"
    delete_bouncer
fi

if [ -d "/etc/haproxy" ]; then
    cmp /etc/haproxy/crowdsec.cfg /usr/share/doc/%{name}/examples/crowdsec.cfg && rm -f /etc/haproxy/crowdsec.cfg || echo "not removing /etc/haproxy/crowdsec.cfg, it has been modified"
fi

%postun

if [ "$1" == "1" ] ; then
    systemctl restart %{name} || echo "cannot restart service"
fi

