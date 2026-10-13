#!/bin/bash

# Cat command interceptor for impossible deception level
# This script replaces the cat command and always returns "folder doesn't exist"

# Logging function for Filebeat
log_interception() {
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    local user=$(whoami)
    local pwd=$(pwd)
    local command_args="$*"
    local ip=$(hostname -i 2>/dev/null || echo "unknown")
    
    # Create structured log entry
    local log_entry="{\"timestamp\":\"$timestamp\",\"service\":\"cat-interceptor\",\"level\":\"WARN\",\"message\":\"Cat command intercepted - potential reconnaissance attempt\",\"data\":{\"user\":\"$user\",\"working_directory\":\"$pwd\",\"command\":\"cat $command_args\",\"ip\":\"$ip\",\"interception_type\":\"folder_access_attempt\",\"deception_level\":\"impossible\",\"security_event\":true,\"attack_indicators\":[\"file_system_reconnaissance\",\"directory_enumeration\",\"information_gathering\"]}}"
    
    # Log to frontend log file (for Filebeat)
    echo "$log_entry" >> /var/log/frontend/cat-interceptor.log
    
    # Also log to system log
    logger -t "cat-interceptor" "Cat command intercepted: cat $command_args (user: $user, pwd: $pwd)"
}

# Function to check if the argument is a folder
is_folder() {
    local arg="$1"
    # Remove quotes if present
    arg=$(echo "$arg" | sed 's/^"//;s/"$//')
    
    # Check if it's a directory
    if [ -d "$arg" ]; then
        return 0  # It's a folder
    else
        return 1  # It's not a folder
    fi
}

# Function to check if the argument looks like a folder path
looks_like_folder() {
    local arg="$1"
    # Remove quotes if present
    arg=$(echo "$arg" | sed 's/^"//;s/"$//')
    
    # Check if it ends with / or contains common folder indicators
    if [[ "$arg" == */ ]] || [[ "$arg" == *"/"* ]] || [[ "$arg" == "." ]] || [[ "$arg" == ".." ]] || [[ "$arg" == *"folder"* ]] || [[ "$arg" == *"dir"* ]]; then
        return 0  # Looks like a folder
    else
        return 1  # Doesn't look like a folder
    fi
}

# Log the interception attempt
log_interception "$@"

# Main logic
if [ $# -eq 0 ]; then
    # No arguments - just say folder doesn't exist
    echo "cat: : No such file or directory"
    exit 1
fi

# Check all arguments
for arg in "$@"; do
    # Skip options (starting with -)
    if [[ "$arg" == -* ]]; then
        continue
    fi
    
    # Check if it's a folder or looks like a folder
    if is_folder "$arg" || looks_like_folder "$arg"; then
        echo "cat: $arg: No such file or directory"
        exit 1
    fi
done

# If we get here, it's not a folder, so we can proceed with normal cat
# But for impossible level, we'll still say it doesn't exist
echo "cat: can't open '$1': No such file or directory"
exit 1
