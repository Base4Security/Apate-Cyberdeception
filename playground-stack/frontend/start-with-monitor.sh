#!/bin/bash

# Startup script that runs both the frontend application and APT monitoring
# APT monitoring only activates on "impossible" deception level

# Get deception level from environment variable
DECEPTION_LEVEL=${DECEPTION_LEVEL:-none}

echo "Deception Level: $DECEPTION_LEVEL"

# Setup deception level configuration
echo "Setting up deception configuration..."
/usr/local/bin/setup-deception.sh

# Only start APK monitor if deception level is "impossible"
if [ "$DECEPTION_LEVEL" = "impossible" ]; then
    echo "Starting APK package installation monitor (IMPOSSIBLE level detected)..."
    /usr/local/bin/apk-monitor.sh &
else
    echo "APK monitoring disabled for deception level: $DECEPTION_LEVEL"
fi

# Start the frontend application
echo "Starting frontend application..."
exec npm start
