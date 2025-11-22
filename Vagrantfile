# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.define "dev" do |vm|
    vm.vm.box = "debian/bookworm64"
    vm.vm.hostname = "crowdsec-spoa-test"
    vm.vm.network "private_network", ip: "192.168.56.10"
    vm.vm.network "forwarded_port", guest: 9090, host: 9090

    vm.vm.provider "libvirt" do |lv|
      lv.memory = "4096"
      lv.cpus = 2
    end

    vm.vm.synced_folder ".", "/vagrant", type: "rsync", rsync__exclude: [".git/", "node_modules/", "*.log"]

    vm.vm.provision "shell", inline: <<-SHELL
      set -e

      # Update system and install base packages
      apt-get update && apt-get upgrade -y
      apt-get install -y tcpdump vim curl wget git build-essential ca-certificates \
        gnupg lsb-release apt-transport-https software-properties-common nginx unzip

      # Install HAProxy 3.1
      curl -fsSL https://haproxy.debian.net/haproxy-archive-keyring.gpg \
        --create-dirs --output /etc/apt/keyrings/haproxy-archive-keyring.gpg
      echo "deb [signed-by=/etc/apt/keyrings/haproxy-archive-keyring.gpg]" \
        https://haproxy.debian.net bookworm-backports-3.1 main > /etc/apt/sources.list.d/haproxy.list
      apt-get update && apt-get install -y haproxy=3.1.*

      # Install Go 1.25.2
      GO_VERSION="1.25.2"
      wget -qO- "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -xzC /usr/local
      echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
      echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.bashrc

      # Install CrowdSec
      curl -s https://install.crowdsec.net | sh
      apt-get install -y crowdsec

      # Install Nuclei for AppSec testing
      NUCLEI_VERSION="3.1.7"
      wget -qO /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
      unzip -q /tmp/nuclei.zip -d /tmp && mv /tmp/nuclei /usr/local/bin/nuclei && chmod +x /usr/local/bin/nuclei
      rm -f /tmp/nuclei.zip
      nuclei -update-templates -silent 2>/dev/null || true

      # Clone CrowdSec Hub
      git clone -q https://github.com/crowdsecurity/hub.git /opt/hub || true

      # Create user and directories
      groupadd -r crowdsec-spoa 2>/dev/null || true
      useradd -r -g crowdsec-spoa -d /opt/crowdsec-spoa-bouncer -s /bin/false crowdsec-spoa 2>/dev/null || true
      mkdir -p /opt/crowdsec-spoa-bouncer /etc/crowdsec/bouncers /var/log/crowdsec-spoa-bouncer \
        /run/crowdsec-spoa /usr/lib/crowdsec-haproxy-spoa-bouncer/lua /var/lib/crowdsec-haproxy-spoa-bouncer/html
      chown -R crowdsec-spoa:crowdsec-spoa /opt/crowdsec-spoa-bouncer /var/log/crowdsec-spoa-bouncer /run/crowdsec-spoa

      # Copy Lua scripts and templates
      mkdir -p /usr/lib/crowdsec-haproxy-spoa-bouncer/lua /var/lib/crowdsec-haproxy-spoa-bouncer/html
      cp /vagrant/lua/*.lua /usr/lib/crowdsec-haproxy-spoa-bouncer/lua/ 2>/dev/null || true
      cp /vagrant/templates/*.html /var/lib/crowdsec-haproxy-spoa-bouncer/html/ 2>/dev/null || true
      chmod 644 /usr/lib/crowdsec-haproxy-spoa-bouncer/lua/*.lua 2>/dev/null || true
      chmod 644 /var/lib/crowdsec-haproxy-spoa-bouncer/html/*.html 2>/dev/null || true

      # Configure nginx
      cat > /etc/nginx/sites-available/default << 'EOF'
server {
    listen 4444 default_server;
    listen [::]:4444 default_server;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    server_name _;

    location / {
        try_files $uri $uri/ =404;
    }
}
EOF

      # Copy and configure HAProxy
      cp /vagrant/config/haproxy.cfg /etc/haproxy/haproxy.cfg 2>/dev/null || true
      cp /vagrant/config/crowdsec.cfg /etc/haproxy/crowdsec.cfg 2>/dev/null || true
      # Update server addresses and remove the second SPOA server (port 9001 doesn't exist)
      sed -i 's/whoami:2020/127.0.0.1:4444/g; s/spoa:9000/127.0.0.1:9000/g; /server s3 spoa:9001/d' \
        /etc/haproxy/haproxy.cfg 2>/dev/null || true
      # Increase SPOA processing timeout to accommodate AppSec calls (AppSec has 5s timeout)
      sed -i 's/timeout\s\+processing\s\+500ms/timeout     processing      6s/' \
        /etc/haproxy/crowdsec.cfg 2>/dev/null || true

      # Copy and configure bouncer
      cp /vagrant/config/crowdsec-spoa-bouncer.yaml.local /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml 2>/dev/null || true
      # Update URLs (match with or without trailing slash) and API key
      sed -i 's|http://crowdsec:8080|http://127.0.0.1:8080|g; s|http://crowdsec:7422|http://127.0.0.1:4241|g; s|api_key:.*|api_key: this_is_a_bad_password|g' \
        /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml 2>/dev/null || true

      # Configure AppSec before starting CrowdSec
      # Install AppSec collections first
      cscli collections install crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules || true
      
      # Configure AppSec acquisition
      mkdir -p /etc/crowdsec/acquis.d
      cat > /etc/crowdsec/acquis.d/appsec.yaml << 'EOF'
appsec_config: crowdsecurity/appsec-default
labels:
  type: appsec
listen_addr: 0.0.0.0:4241
source: appsec
EOF

      # Now start all services with CrowdSec properly configured
      systemctl enable --now nginx haproxy crowdsec
      sleep 5
      cscli bouncers add crowdsec-spoa-bouncer --key this_is_a_bad_password 2>/dev/null || true
    SHELL

    vm.vm.provision "shell", run: "always", inline: <<-SHELL
      set -e
      export PATH=$PATH:/usr/local/go/bin

      # Build SPOA bouncer
      if [ -f "/vagrant/main.go" ]; then
        cd /vagrant
        if go build -ldflags="-s -w" -o /opt/crowdsec-spoa-bouncer/crowdsec-spoa-bouncer .; then
          chown crowdsec-spoa:crowdsec-spoa /opt/crowdsec-spoa-bouncer/crowdsec-spoa-bouncer
          chmod +x /opt/crowdsec-spoa-bouncer/crowdsec-spoa-bouncer

          # Install systemd service
          cp /vagrant/config/crowdsec-spoa-bouncer.service /etc/systemd/system/crowdsec-spoa-bouncer.service
          sed -i 's|${BIN}|/opt/crowdsec-spoa-bouncer/crowdsec-spoa-bouncer|g; s|${CFG}|/etc/crowdsec/bouncers|g' \
            /etc/systemd/system/crowdsec-spoa-bouncer.service
          sed -i 's|Type=notify|Type=simple|g; /ExecStartPre=/d' \
            /etc/systemd/system/crowdsec-spoa-bouncer.service

          systemctl daemon-reload
          systemctl enable --now crowdsec-spoa-bouncer
        fi
      fi

      # Restart services in order
      systemctl restart nginx
      sleep 2
      systemctl restart crowdsec-spoa-bouncer 2>/dev/null || true
      sleep 3
      systemctl restart haproxy

      # Verify services
      for svc in nginx crowdsec-spoa-bouncer haproxy; do
        systemctl is-active --quiet $svc && echo "✅ $svc: running" || echo "❌ $svc: failed"
      done
    SHELL
  end
end
