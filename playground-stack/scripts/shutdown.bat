@echo off
REM Shutdown script for Cyber Deception Playground (Windows)
REM Removes all containers and volumes for every deployment level

setlocal enabledelayedexpansion

echo ==========================================
echo Cyber Deception Playground Shutdown
echo ==========================================
echo.
echo This script will:
echo - Stop cyberdeception-playground running containers
echo - Remove cyberdeception-playground containers
echo - Remove cyberdeception-playground volumes
echo - Clean up networks
echo.
echo WARNING: This will permanently delete all data!
echo.

set /p CONFIRM="Are you sure you want to proceed? (y/n): "
if /i not "%CONFIRM%"=="y" (
    echo Shutdown cancelled. See you later!
    exit /b 0
)

echo.
echo ==========================================
echo Stopping and Removing Containers
echo ==========================================

echo Stopping cyberdeception-playground containers...
docker-compose --profile none down --remove-orphans
docker-compose --profile basic down --remove-orphans
docker-compose --profile complete down --remove-orphans
docker-compose --profile impossible down --remove-orphans

echo.
echo ==========================================
echo Removing Volumes
echo ==========================================

docker volume rm cyberdeception-playground_mysql_data 2>nul
docker volume rm cyberdeception-playground_elasticsearch_data 2>nul
docker volume rm cyberdeception-playground_kibana_data 2>nul
docker volume rm cyberdeception-playground_logs 2>nul

echo.
echo ==========================================
echo Cleaning Networks
echo ==========================================

echo Removing custom networks...
docker network rm playground-server-network 2>nul
docker network rm playground-database-network 2>nul
docker network rm playground-monitor-network 2>nul
docker network rm playground-external-network 2>nul
docker network rm playground-dmz-network 2>nul
docker network rm playground-decoy-network 2>nul

echo.
echo ==========================================
echo Final Cleanup
echo ==========================================

set /p REMOVE_IMAGES="Remove Docker playground images as well? (y/n): "
if /i "%REMOVE_IMAGES%"=="y" (
    echo Removing Docker playground images...
    docker image prune -a -f --filter label=com.docker.compose.project=cyberdeception-playground
)

set /p REMOVE_LOGS="Remove local log files as well? (y/n): "
if /i "%REMOVE_LOGS%"=="y" (
    echo Removing local log files...
    if exist "..\logs\frontend" (
        del /s /q "..\logs\frontend\*"
        echo Local frontend log files removed.
    ) else (
        echo No frontend log files found.
    )
    if exist "..\logs\backend" (
        del /s /q "..\logs\backend\*"
        echo Local backend log files removed.
    ) else (
        echo No backend log files found.
    )
    if exist "..\logs\mysql" (
        del /s /q "..\logs\mysql\*"
        echo Local mysql log files removed.
    ) else (
        echo No mysql log files found.
    )
)

echo.
echo ==========================================
echo Shutdown Complete! See you later!
echo ==========================================
echo.

pause
