# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Use Debian 12 (Bookworm) as the base box
  config.vm.box = "debian/bookworm64"

  # Configure the VM
  config.vm.hostname = "crowdsec-spoa-test"
  config.vm.network "private_network", ip: "192.168.56.10"

  # Forward ports for testing
  config.vm.network "forwarded_port", guest: 9090, host: 9090  # HAProxy stats

  # VM resources
  config.vm.provider "libvirt" do |lv|
    lv.memory = "4096"
    lv.cpus = 2
  end

  # Provision the VM
  config.vm.provision "shell", inline: <<-SHELL
    set -e

    echo "🚀 Setting up CrowdSec SPOA Bouncer Test Environment..."

    # Update system
    apt-get update
    apt-get upgrade -y

    # Install required packages
    apt-get install -y \
      tcpdump \
      vim \
      curl \
      wget \
      git \
      build-essential \
      ca-certificates \
      gnupg \
      lsb-release \
      apt-transport-https \
      software-properties-common \
      nginx \
      unzip

    # Install HAProxy from official repository (latest version)
    echo "⚙️ Installing HAProxy 3.1..."
    curl https://haproxy.debian.net/haproxy-archive-keyring.gpg \
      --create-dirs --output /etc/apt/keyrings/haproxy-archive-keyring.gpg
    echo "deb [signed-by=/etc/apt/keyrings/haproxy-archive-keyring.gpg]" \
      https://haproxy.debian.net bookworm-backports-3.1 main \
      > /etc/apt/sources.list.d/haproxy.list
    apt-get update
    apt-get install -y haproxy=3.1.*

    # Install Go (version specified in go.mod)
    echo "📦 Installing Go..."
    GO_VERSION="1.24.4"
    wget -O go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go.tar.gz
    rm go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.bashrc

    # Install CrowdSec
    echo "🛡️ Installing CrowdSec..."
    curl -s https://install.crowdsec.net | sudo sh
    apt-get install -y crowdsec

    # Clone CrowdSec Hub repository for AppSec testing
    echo "📚 Cloning CrowdSec Hub repository..."
    git clone https://github.com/crowdsecurity/hub.git /opt/hub

    # Install Nuclei for AppSec testing
    echo "🔍 Installing Nuclei..."
    NUCLEI_VERSION="3.1.7"
    wget -O nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
    unzip nuclei.zip
    mv nuclei /usr/local/bin/nuclei
    chmod +x /usr/local/bin/nuclei
    rm nuclei.zip
    
    # Update Nuclei templates
    nuclei -update-templates

    # Configure nginx for testing
    echo "🌐 Configuring nginx..."
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

    # Enable and start nginx
    systemctl enable nginx
    systemctl start nginx

    # Create crowdsec-spoa user and group
    echo "👤 Creating crowdsec-spoa user and group..."
    groupadd -r crowdsec-spoa
    useradd -r -g crowdsec-spoa -d /opt/crowdsec-spoa-bouncer -s /bin/false crowdsec-spoa

    # Create directories for our application
    mkdir -p /opt/crowdsec-spoa-bouncer
    mkdir -p /etc/crowdsec/bouncers
    mkdir -p /var/log/crowdsec-spoa-bouncer
    mkdir -p /run/crowdsec-spoa
    
    # Set proper ownership
    chown -R crowdsec-spoa:crowdsec-spoa /opt/crowdsec-spoa-bouncer
    chown -R crowdsec-spoa:crowdsec-spoa /var/log/crowdsec-spoa-bouncer
    chown -R crowdsec-spoa:crowdsec-spoa /run/crowdsec-spoa

    # Create Lua directories and copy Lua scripts
    echo "📜 Setting up Lua scripts and templates..."
    mkdir -p /usr/lib/crowdsec-haproxy-spoa-bouncer/lua
    mkdir -p /var/lib/crowdsec/lua/haproxy/templates
    
    # Copy Lua scripts
    cp /vagrant/lua/*.lua /usr/lib/crowdsec-haproxy-spoa-bouncer/lua/
    
    # Copy HTML templates
    cp /vagrant/templates/*.html /var/lib/crowdsec/lua/haproxy/templates/
    
    # Set proper permissions
    chmod 644 /usr/lib/crowdsec-haproxy-spoa-bouncer/lua/*.lua
    chmod 644 /var/lib/crowdsec/lua/haproxy/templates/*.html

    # Copy HAProxy configuration files
    echo "⚙️ Configuring HAProxy..."
    cp /vagrant/config/haproxy.cfg /etc/haproxy/haproxy.cfg
    cp /vagrant/config/crowdsec.cfg /etc/haproxy/crowdsec.cfg
    
    # Update HAProxy config to use loopback addresses
    echo "🔧 Updating HAProxy config for Vagrant environment..."
    sed -i 's/whoami:2020/127.0.0.1:4444/g' /etc/haproxy/haproxy.cfg
    sed -i 's/spoa:9000/127.0.0.1:9000/g' /etc/haproxy/haproxy.cfg
    sed -i 's/spoa:9001/127.0.0.1:9001/g' /etc/haproxy/haproxy.cfg

    # Copy bouncer configuration
    cp /vagrant/config/crowdsec-spoa-bouncer.yaml.local /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml
    
    # Update bouncer config to use loopback addresses and correct API key
    echo "🔧 Updating bouncer config for Vagrant environment..."
    sed -i 's|http://crowdsec:8080/|http://127.0.0.1:8080/|g' /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml
    sed -i 's|http://crowdsec:7422/|http://127.0.0.1:4241/|g' /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml

    # Start services
    echo "🚀 Starting services..."
    systemctl enable haproxy
    systemctl start haproxy

    systemctl enable crowdsec
    systemctl start crowdsec

    # Wait for CrowdSec to be ready
    sleep 10

    # Register the bouncer
    echo "🔑 Registering SPOA bouncer..."
    cscli bouncers add crowdsec-spoa-bouncer --key this_is_a_bad_password

    echo "✅ Setup complete!"
    echo ""
    echo "🎯 Test endpoints:"
    echo "  - HAProxy frontend: http://192.168.56.10:8080"
    echo "  - HAProxy stats: http://192.168.56.10:9090/stats"
    echo "  - CrowdSec API: http://192.168.56.10:4242"
    echo "  - CrowdSec AppSec: http://192.168.56.10:7422"
    echo ""
    echo "📋 Next steps:"
    echo "  1. Copy your SPOA binary to /opt/crowdsec-spoa-bouncer/"
    echo "  2. Create systemd service for SPOA"
    echo "  3. Start SPOA service"
    echo "  4. Test AppSec functionality"
  SHELL

  # Sync the project directory
  config.vm.synced_folder ".", "/vagrant", type: "rsync", rsync__exclude: [".git/", "node_modules/", "*.log"]

  # Post-provision script
  config.vm.provision "shell", run: "always", inline: <<-SHELL
    echo "🔄 Post-provision setup..."
    
    # Make sure Go is in PATH for this session
    export PATH=$PATH:/usr/local/go/bin
    
    # Build the SPOA bouncer if source is available
    if [ -f "/vagrant/main.go" ]; then
      echo "🔨 Building SPOA bouncer..."
      cd /vagrant
      
      # Check Go version
      echo "Go version: $(/usr/local/go/bin/go version)"
      
      # Build with optimizations to reduce memory usage
      export GOGC=50
      export GOMAXPROCS=1
      if /usr/local/go/bin/go build -ldflags="-s -w" -o /opt/crowdsec-spoa-bouncer/crowdsec-spoa-bouncer .; then
        echo "✅ Build successful!"
        
        # Verify binary was created
        if [ -f "/opt/crowdsec-spoa-bouncer/crowdsec-spoa-bouncer" ]; then
          echo "✅ Binary created successfully"
          ls -la /opt/crowdsec-spoa-bouncer/crowdsec-spoa-bouncer
          
          # Set proper ownership
          chown crowdsec-spoa:crowdsec-spoa /opt/crowdsec-spoa-bouncer/crowdsec-spoa-bouncer
          chmod +x /opt/crowdsec-spoa-bouncer/crowdsec-spoa-bouncer
        else
          echo "❌ Binary was not created"
          exit 1
        fi
      else
        echo "❌ Build failed!"
        exit 1
      fi
      
      # Copy and configure systemd service for SPOA
      cp /vagrant/config/crowdsec-spoa-bouncer.service /etc/systemd/system/crowdsec-spoa-bouncer.service
      
      # Replace variables in the service file
      sed -i 's|${BIN}|/opt/crowdsec-spoa-bouncer/crowdsec-spoa-bouncer|g' /etc/systemd/system/crowdsec-spoa-bouncer.service
      sed -i 's|${CFG}|/etc/crowdsec/bouncers|g' /etc/systemd/system/crowdsec-spoa-bouncer.service
      
      # Change service type from notify to simple for testing
      sed -i 's|Type=notify|Type=simple|g' /etc/systemd/system/crowdsec-spoa-bouncer.service
      
      # Remove ExecStartPre commands that might not work in test environment
      sed -i '/ExecStartPre=/d' /etc/systemd/system/crowdsec-spoa-bouncer.service

      # Enable and start SPOA service
      systemctl daemon-reload
      systemctl enable crowdsec-spoa-bouncer
      systemctl start crowdsec-spoa-bouncer
      
      echo "✅ SPOA bouncer built and started!"
    else
      echo "⚠️  Source code not found, skipping build"
      echo "Available files in /vagrant:"
      ls -la /vagrant/
    fi

    # Restart services in proper order to ensure connectivity
    echo "🔄 Restarting services in proper order..."
    
    # 1. Restart nginx first (backend)
    echo "1️⃣ Restarting nginx..."
    systemctl restart nginx
    sleep 2
    
    # 2. Restart SPOA bouncer (middleware)
    echo "2️⃣ Restarting SPOA bouncer..."
    systemctl restart crowdsec-spoa-bouncer
    sleep 3
    
    # 3. Restart HAProxy last (frontend) - ensures it can connect to SPOA and nginx
    echo "3️⃣ Restarting HAProxy..."
    systemctl restart haproxy
    sleep 2
    
    # Verify all services are running
    echo "🔍 Verifying service status..."
    systemctl is-active --quiet nginx && echo "✅ nginx: running" || echo "❌ nginx: failed"
    systemctl is-active --quiet crowdsec-spoa-bouncer && echo "✅ SPOA bouncer: running" || echo "❌ SPOA bouncer: failed"
    systemctl is-active --quiet haproxy && echo "✅ HAProxy: running" || echo "❌ HAProxy: failed"
    
    echo "🎉 All services restarted in proper order!"
  SHELL
end
