@echo off
REM Master startup script for Cyber Deception Playground (Windows)
REM Supports different deception levels: none, basic, complete, impossible

setlocal enabledelayedexpansion

echo ==========================================
echo Cyber Deception Playground Startup
echo ==========================================
echo Welcome to the Cyber Deception Playground!
echo This is a comprehensive cybersecurity training environment
echo that simulates attack scenarios with various
echo levels of deception techniques.
echo.
echo For detailed documentation, visit:
echo https://github.com/Base4Security/cyberdeception-playground
echo.

REM Default values
set DECEPTION_LEVEL=%1
if "%DECEPTION_LEVEL%"=="" (
    echo.
    echo ==========================================
    echo Select Deception Level
    echo ==========================================
    echo 1. none      -     Production services only
    echo 2. basic     -     Production + SSH Honeypot
    echo 3. complete  -     Production + deception activities
    echo 4. impossible -    Production + A lot of deception activities
    echo ==========================================
    set /p DECEPTION_LEVEL="Enter deception level (1-4 or none/basic/complete/impossible): "
    echo.
)

REM Convert number to level name if needed
if "%DECEPTION_LEVEL%"=="1" set DECEPTION_LEVEL=none
if "%DECEPTION_LEVEL%"=="2" set DECEPTION_LEVEL=basic
if "%DECEPTION_LEVEL%"=="3" set DECEPTION_LEVEL=complete
if "%DECEPTION_LEVEL%"=="4" set DECEPTION_LEVEL=impossible

REM Validate deception level
if not "%DECEPTION_LEVEL%"=="none" if not "%DECEPTION_LEVEL%"=="basic" if not "%DECEPTION_LEVEL%"=="complete" if not "%DECEPTION_LEVEL%"=="impossible" (
    echo Error: Invalid deception level: %DECEPTION_LEVEL%
    echo Valid levels: 1-4 or none, basic, complete, impossible
    exit /b 1
)

echo ==========================================
echo Deception Level to deploy: %DECEPTION_LEVEL%
echo ==========================================

set /p READY="Ready? (y/n): "
if "%READY%"=="y" goto :start
if "%READY%"=="n" exit /b 0
echo Wrong answer
exit /b 1

:start

REM Start services based on deception level
echo.
if "%DECEPTION_LEVEL%"=="none" goto :none_level
if "%DECEPTION_LEVEL%"=="basic" goto :basic_level
if "%DECEPTION_LEVEL%"=="complete" goto :complete_level
if "%DECEPTION_LEVEL%"=="impossible" goto :impossible_level

:none_level
echo Starting Prod services and monitoring (deception services disabled)
set DECEPTION_LEVEL=%DECEPTION_LEVEL%
docker-compose --profile none up -d
if errorlevel 1 (
    echo ERROR: Docker compose failed
    exit /b 1
)
goto :continue

:basic_level
echo Starting Prod services monitoring and a SSH honeypot
set DECEPTION_LEVEL=%DECEPTION_LEVEL%
docker-compose --profile basic up -d
if errorlevel 1 (
    echo ERROR: Docker compose failed
    exit /b 1
)
goto :continue

:complete_level
echo Starting all services with more deception activities
set DECEPTION_LEVEL=%DECEPTION_LEVEL%
docker-compose --profile complete up -d
if errorlevel 1 (
    echo ERROR: Docker compose failed
    exit /b 1
)
goto :continue

:impossible_level
echo Starting all services with a lot of deception activities
set DECEPTION_LEVEL=%DECEPTION_LEVEL%
docker-compose --profile impossible up -d
if errorlevel 1 (
    echo ERROR: Docker compose failed
    exit /b 1
)
goto :continue

:continue

echo.
echo ==========================================
echo Docker Services Status
echo ==========================================
docker-compose ps

echo.
echo ==========================================
echo Docker Networks Status
echo ==========================================
docker network ls | findstr "playground-server-network playground-database-network playground-monitor-network playground-external-network playground-dmz-network playground-decoy-network"
echo.
echo ==========================================
echo Defender GUI Access Information
echo ==========================================
echo Frontend: http://localhost:3000
echo Kibana: http://localhost:5601
echo.
echo ==========================================
echo Attacker Access Information:
echo ==========================================
echo docker exec -it attacker-tools /bin/bash
echo.
echo ==========================================
echo Startup Complete of Deception Level: %DECEPTION_LEVEL%!
echo ==========================================

pause
