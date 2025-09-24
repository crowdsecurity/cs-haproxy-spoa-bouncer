#!/bin/bash

# AppSec Testing Script using host networking
# This script runs CrowdSec on the host and tests via hubtest

set -e

echo "🛡️  Starting AppSec Test Sequence..."

# Step 1: Start CrowdSec on the host
echo "📋 Step 1: Starting CrowdSec on host..."
echo "   Make sure CrowdSec is running with AppSec enabled on port 7422"
echo "   You can start it with: docker run -d --name crowdsec-test -p 7422:7422 crowdsecurity/crowdsec:latest"
echo "   Or use your local CrowdSec installation"
echo ""

# Step 2: Start the test environment (SPOA + HAProxy)
echo "📋 Step 2: Starting SPOA and HAProxy test environment..."
podman-compose -f docker-compose.test.yaml up --build -d

# Wait for services to be ready
echo "📋 Step 3: Waiting for services to be ready..."
sleep 10

# Step 4: Run hubtest from host
echo "📋 Step 4: Running AppSec HubTest..."
if command -v cscli &> /dev/null; then
    # Run hubtest if cscli is available
    cscli hubtest run --appsec --all --target http://localhost:9090 --host localhost:7422
else
    echo "   cscli not found on host. Please run hubtest manually:"
    echo "   cscli hubtest run --appsec --all --target http://localhost:9090 --host localhost:7422"
fi

# Step 5: Show test results
echo "📋 Step 5: Test completed!"
echo ""
echo "💡 Check the logs:"
echo "   podman-compose -f docker-compose.test.yaml logs spoa"
echo "   podman-compose -f docker-compose.test.yaml logs haproxy"

# Step 6: Clean up
echo "📋 Step 6: Cleaning up test environment..."
podman-compose -f docker-compose.test.yaml down

echo "✅ AppSec test sequence completed!"
