#!/bin/bash

# Shutdown script for Cyber Deception Playground (Linux)
# Removes all containers and volumes for every deployment level

set -e

echo "=========================================="
echo "Cyber Deception Playground Shutdown"
echo "=========================================="
echo ""
echo "This script will:"
echo "- Stop cyberdeception-playground running containers"
echo "- Remove cyberdeception-playground containers"
echo "- Remove cyberdeception-playground volumes"
echo "- Clean up networks"
echo ""
echo "WARNING: This will permanently delete all data!"
echo ""

read -p "Are you sure you want to proceed? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Shutdown cancelled. See you later!"
    exit 0
fi

echo ""
echo "=========================================="
echo "Stopping and Removing Containers"
echo "=========================================="

echo "Stopping cyberdeception-playground containers..."
docker-compose --profile none down --remove-orphans 2>/dev/null || true
docker-compose --profile basic down --remove-orphans 2>/dev/null || true
docker-compose --profile complete down --remove-orphans 2>/dev/null || true
docker-compose --profile impossible down --remove-orphans 2>/dev/null || true

echo ""
echo "=========================================="
echo "Removing Volumes"
echo "=========================================="

docker volume rm cyberdeception-playground_mysql_data 2>/dev/null || echo "MySQL volume not found or already removed"
docker volume rm cyberdeception-playground_elasticsearch_data 2>/dev/null || echo "Elasticsearch volume not found or already removed"
docker volume rm cyberdeception-playground_kibana_data 2>/dev/null || echo "Kibana volume not found or already removed"
docker volume rm cyberdeception-playground_logs 2>/dev/null || echo "Logs volume not found or already removed"

echo ""
echo "=========================================="
echo "Cleaning Networks"
echo "=========================================="

echo "Removing custom networks..."
docker network rm playground-server-network 2>/dev/null || echo "playground-server-network not found or already removed"
docker network rm playground-database-network 2>/dev/null || echo "playground-database-network not found or already removed"
docker network rm playground-monitor-network 2>/dev/null || echo "playground-monitor-network not found or already removed"
docker network rm playground-external-network 2>/dev/null || echo "playground-external-network not found or already removed"
docker network rm playground-dmz-network 2>/dev/null || echo "playground-dmz-network not found or already removed"
docker network rm playground-decoy-network 2>/dev/null || echo "playground-decoy-network not found or already removed"

echo ""
echo "=========================================="
echo "Final Cleanup"
echo "=========================================="

read -p "Remove Docker playground images as well? (y/n): " REMOVE_IMAGES
if [ "$REMOVE_IMAGES" = "y" ] || [ "$REMOVE_IMAGES" = "Y" ]; then
    echo "Removing Docker playground images..."
    docker image prune -a -f --filter label=com.docker.compose.project=cyberdeception-playground 2>/dev/null || echo "No playground images found to remove"
fi

read -p "Remove local log files as well? (y/n): " REMOVE_LOGS
if [ "$REMOVE_LOGS" = "y" ] || [ "$REMOVE_LOGS" = "Y" ]; then
    echo "Removing local log files..."
    if [ -d "../logs/frontend" ]; then
        rm -rf "../logs/frontend"/*
        echo "Local frontend log files removed."
    else
        echo "No frontend log files found."
    fi
    if [ -d "../logs/backend" ]; then
        rm -rf "../logs/backend"/*
        echo "Local backend log files removed."
    else
        echo "No backend log files found."
    fi
    if [ -d "../logs/mysql" ]; then
        rm -rf "../logs/mysql"/*
        echo "Local mysql log files removed."
    else
        echo "No mysql log files found."
    fi
fi

echo ""
echo "=========================================="
echo "Shutdown Complete! See you later!"
echo "=========================================="
echo ""

echo "Press Enter to continue..."
read
