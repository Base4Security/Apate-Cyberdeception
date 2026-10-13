#!/bin/bash

# Master startup script for Cyber Deception Playground (Linux)
# Supports different deception levels: none, basic, complete, impossible

set -e

echo "=========================================="
echo "Cyber Deception Playground Startup"
echo "=========================================="
echo "Welcome to the Cyber Deception Playground!"
echo "This is a comprehensive cybersecurity training environment"
echo "that simulates attack scenarios with various"
echo "levels of deception techniques."
echo ""
echo "For detailed documentation, visit:"
echo "https://github.com/Base4Security/cyberdeception-playground"
echo ""

# Default values
DECEPTION_LEVEL="$1"

if [ -z "$DECEPTION_LEVEL" ]; then
    echo ""
    echo "=========================================="
    echo "Select Deception Level"
    echo "=========================================="
    echo "1. none      -     Production services only"
    echo "2. basic     -     Production + SSH Honeypot"
    echo "3. complete  -     Production + deception activities"
    echo "4. impossible -    Production + A lot of deception activities"
    echo "=========================================="
    read -p "Enter deception level (1-4 or none/basic/complete/impossible): " DECEPTION_LEVEL
    echo ""
fi

# Convert number to level name if needed
case "$DECEPTION_LEVEL" in
    "1") DECEPTION_LEVEL="none" ;;
    "2") DECEPTION_LEVEL="basic" ;;
    "3") DECEPTION_LEVEL="complete" ;;
    "4") DECEPTION_LEVEL="impossible" ;;
esac

# Validate deception level
case "$DECEPTION_LEVEL" in
    "none"|"basic"|"complete"|"impossible")
        ;;
    *)
        echo "Error: Invalid deception level: $DECEPTION_LEVEL"
        echo "Valid levels: 1-4 or none, basic, complete, impossible"
        exit 1
        ;;
esac

echo "=========================================="
echo "Deception Level to deploy: $DECEPTION_LEVEL"
echo "=========================================="

read -p "Ready? (y/n): " READY
if [ "$READY" = "y" ]; then
    echo "Starting deployment..."
elif [ "$READY" = "n" ]; then
    echo "Deployment cancelled."
    exit 0
else
    echo "Invalid answer. Exiting."
    exit 1
fi

# Start services based on deception level
echo ""
case "$DECEPTION_LEVEL" in
    "none")
        echo "Starting Prod services and monitoring (deception services disabled)"
        export DECEPTION_LEVEL="$DECEPTION_LEVEL"
        docker-compose --profile none up -d
        ;;
    "basic")
        echo "Starting Prod services monitoring and a SSH honeypot"
        export DECEPTION_LEVEL="$DECEPTION_LEVEL"
        docker-compose --profile basic up -d
        ;;
    "complete")
        echo "Starting all services with more deception activities"
        export DECEPTION_LEVEL="$DECEPTION_LEVEL"
        docker-compose --profile complete up -d
        ;;
    "impossible")
        echo "Starting all services with a lot of deception activities"
        export DECEPTION_LEVEL="$DECEPTION_LEVEL"
        docker-compose --profile impossible up -d
        ;;
esac

if [ $? -ne 0 ]; then
    echo "ERROR: Docker compose failed"
    exit 1
fi

echo ""
echo "=========================================="
echo "Docker Services Status"
echo "=========================================="
docker-compose ps

echo ""
echo "=========================================="
echo "Docker Networks Status"
echo "=========================================="
docker network ls | grep -E "playground-server-network|playground-database-network|playground-monitor-network|playground-external-network|playground-dmz-network|playground-decoy-network" || echo "No playground networks found"

echo ""
echo "=========================================="
echo "Defender GUI Access Information"
echo "=========================================="
echo "Frontend: http://localhost:3000"
echo "Kibana: http://localhost:5601"
echo ""
echo "=========================================="
echo "Attacker Access Information:"
echo "=========================================="
echo "docker exec -it attacker-tools /bin/bash"
echo ""
echo "=========================================="
echo "Startup Complete of Deception Level: $DECEPTION_LEVEL!"
echo "=========================================="

echo ""
echo "Press Enter to continue..."
read
