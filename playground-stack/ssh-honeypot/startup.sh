#!/bin/bash

# Startup script for Real SSH Honeypot
# This script starts a real SSH server with monitoring

echo "Starting Real SSH Honeypot..."

# Start SSH server
echo "Starting SSH server..."
service ssh start

# Start monitoring in background
echo "Starting SSH monitoring..."
python3 /app/ssh_honeypot.py &
MONITOR_PID=$!

# Keep the container running
echo "SSH server and monitoring started"
echo "SSH server is running on port 22"
echo "Monitoring PID: $MONITOR_PID"

# Wait for SSH server to be ready
sleep 5

# Show SSH server status
echo "SSH server status:"
service ssh status

# Keep container alive
while true; do
    sleep 30
    if ! kill -0 $MONITOR_PID 2>/dev/null; then
        echo "Monitor process died, restarting..."
        python3 /app/ssh_honeypot.py &
        MONITOR_PID=$!
    fi
done
