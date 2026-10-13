#!/bin/bash

# Script to select the appropriate init SQL file based on DECEPTION_LEVEL
# This allows the MySQL container to initialize with different data sets

set -e

# Default to 'none' if DECEPTION_LEVEL is not set
DECEPTION_LEVEL=${DECEPTION_LEVEL:-none}

echo "MySQL initialization script starting..."
echo "Deception level: $DECEPTION_LEVEL"

# Create the appropriate init file based on deception level
case "$DECEPTION_LEVEL" in
    "none")
        echo "Using init-none.sql for production-only setup"
        cp /tmp/init-none.sql /docker-entrypoint-initdb.d/init.sql
        ;;
    "basic")
        echo "Using init-basic.sql for basic deception setup"
        cp /tmp/init-basic.sql /docker-entrypoint-initdb.d/init.sql
        ;;
    "complete")
        echo "Using init-complete.sql for complete deception setup"
        cp /tmp/init-complete.sql /docker-entrypoint-initdb.d/init.sql
        ;;
    "impossible")
        echo "Using init-impossible.sql for impossible deception setup"
        cp /tmp/init-impossible.sql /docker-entrypoint-initdb.d/init.sql
        ;;
    *)
        echo "Unknown deception level: $DECEPTION_LEVEL, defaulting to 'none'"
        cp /tmp/init-none.sql /docker-entrypoint-initdb.d/init.sql
        ;;
esac

echo "Selected initialization file: /docker-entrypoint-initdb.d/init.sql"

# Execute the original MySQL entrypoint with the selected init file
exec /usr/local/bin/docker-entrypoint.sh mysqld "$@"
