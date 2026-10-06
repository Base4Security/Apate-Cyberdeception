#!/bin/bash

# APK Package Installation Monitor and Auto-Removal Script
# This script monitors for unauthorized package installations and removes them immediately

LOG_FILE="/var/log/frontend/apk-monitor.log"
LOCK_FILE="/tmp/apk-monitor.lock"
BASELINE_FILE="/tmp/apk-baseline.txt"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to create baseline of installed packages
create_baseline() {
    log_message "Creating package baseline..."
    apk info | sort > "$BASELINE_FILE"
    local package_count=$(wc -l < "$BASELINE_FILE")
    log_message "Baseline created with $package_count packages"
}

# Function to get current package list
get_current_packages() {
    apk info | sort
}

# Function to detect new packages
detect_new_packages() {
    if [ ! -f "$BASELINE_FILE" ]; then
        log_message "No baseline found, creating new baseline"
        create_baseline
        return 0
    fi
    
    local current_packages=$(get_current_packages)
    local new_packages=$(comm -13 "$BASELINE_FILE" <(echo "$current_packages"))
    
    if [ -n "$new_packages" ]; then
        log_message "WARNING: New packages detected!"
        echo "$new_packages" | while read package; do
            if [ -n "$package" ]; then
                log_message "NEW PACKAGE: $package"
            fi
        done
        # Store new packages in a temporary file for processing
        echo "$new_packages" > "/tmp/new-packages.txt"
        return 1
    fi
    return 0
}

# Function to remove new packages
remove_new_packages() {
    detect_new_packages
    local exit_code=$?
    
    if [ $exit_code -eq 1 ] && [ -f "/tmp/new-packages.txt" ]; then
        log_message "Removing unauthorized new packages..."
        
        # Read packages from temporary file and remove them
        while IFS= read -r package; do
            if [ -n "$package" ] && [ "$package" != " " ]; then
                log_message "Removing unauthorized package: $package"
                
                # Retry logic: try up to 3 times
                local retry_count=0
                local max_retries=3
                local success=false
                
                while [ $retry_count -lt $max_retries ] && [ "$success" = false ]; do
                    if apk del "$package" 2>/dev/null; then
                        log_message "Successfully removed $package"
                        success=true
                    else
                        retry_count=$((retry_count + 1))
                        if [ $retry_count -lt $max_retries ]; then
                            log_message "Failed to remove $package (attempt $retry_count), retrying..."
                            sleep 2
                        else
                            log_message "Failed to remove $package after $max_retries attempts"
                        fi
                    fi
                done
            fi
        done < "/tmp/new-packages.txt"
        
        # Clean up temporary file
        rm -f "/tmp/new-packages.txt"
        
        # Update baseline after removal
        create_baseline
    fi
}

# Function to check if apk is running
is_apk_running() {
    pgrep -f "apk\|add\|del\|upgrade" > /dev/null 2>&1
}


# Function to monitor apk processes
monitor_apk_processes() {
    while true; do
        if is_apk_running; then
            log_message "APK process detected - monitoring for unauthorized installations"
            
            # Wait for apk to finish
            while is_apk_running; do
                sleep 2
            done
            
            # Check for new installations and remove them
            check_for_new_packages
        fi
        
        sleep 5
    done
}

# Function to check for any new packages (replaces static list approach)
check_for_new_packages() {
    log_message "Checking for any new packages..."
    remove_new_packages
}

# Function to test monitoring
test_monitoring() {
    log_message "Testing APK monitoring functionality..."
    log_message "Current installed packages:"
    apk info | head -10 | while read package; do
        log_message "  - $package"
    done
    
    # Create initial baseline
    create_baseline
    log_message "APK monitoring test complete"
}

# Function to setup monitoring
setup_monitoring() {
    local deception_level=${DECEPTION_LEVEL:-none}
    log_message "Starting APK Package Installation Monitor (Deception Level: $deception_level)"
    
    # Run initial test
    test_monitoring
    
    # Create log file if it doesn't exist
    touch "$LOG_FILE"
    
    # Set up file system monitoring for apk logs
    if command -v inotifywait >/dev/null 2>&1; then
        log_message "Setting up inotify monitoring for apk logs"
        (
            while inotifywait -e modify /var/log/apk.log 2>/dev/null; do
                log_message "APK log modified - checking for new installations"
                check_for_new_packages
            done
        ) &
    else
        log_message "inotifywait not available - using polling method"
    fi
    
    # Start the main monitoring loop
    monitor_apk_processes &
    
    # Periodic checks for new packages
    (
        while true; do
            sleep 4
            log_message "Running periodic new package check..."
            check_for_new_packages
        done
    ) &
    
    # Monitor for any new package installations
    (
        while true; do
            sleep 5
            if is_apk_running; then
                log_message "APK process detected - monitoring installation..."
                # Wait for apk to finish
                while is_apk_running; do
                    sleep 1
                done
                log_message "APK process finished - checking for new packages..."
                check_for_new_packages
            fi
        done
    ) &
    
    log_message "APK monitoring setup complete"
}

# Function to clean up on exit
cleanup() {
    log_message "Stopping APK monitor"
    rm -f "$LOCK_FILE"
    exit 0
}

# Main execution
main() {
    # Check deception level - only run on impossible level
    local deception_level=${DECEPTION_LEVEL:-none}
    if [ "$deception_level" != "impossible" ]; then
        log_message "APK monitor disabled for deception level: $deception_level (only runs on 'impossible')"
        exit 0
    fi
    
    # Check if already running
    if [ -f "$LOCK_FILE" ]; then
        log_message "APK monitor already running"
        exit 1
    fi
    
    # Create lock file
    touch "$LOCK_FILE"
    
    # Set up signal handlers
    trap cleanup SIGTERM SIGINT
    
    # Start monitoring
    setup_monitoring
    
    # Keep the script running
    wait
}

# Run the main function
main "$@"
