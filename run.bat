@echo off
setlocal EnableDelayedExpansion

:: Configuration - Edit these values
set CLOUDFLARE_TOKEN=example
set DOMAIN=example.org
set SUBDOMAIN=example

echo ===============================
echo    IP Changer Script Runner
echo ===============================
echo.

:: Check and install PowerShell 7 if needed
echo Checking PowerShell 7 installation...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0ispwsh7installed.ps1" -Check >nul 2>&1
if errorlevel 1 (
    echo PowerShell 7 is not installed. Installing now...
    echo This may take a few minutes and require administrator privileges.
    powershell.exe -ExecutionPolicy Bypass -File "%~dp0ispwsh7installed.ps1" -Install
    if errorlevel 1 (
        echo.
        echo ERROR: PowerShell 7 installation failed!
        echo This script requires PowerShell 7 to function properly.
        echo Please install PowerShell 7 manually and try again.
        pause
        exit /b 1
    )
    echo PowerShell 7 installation completed successfully.
    echo Refreshing environment variables...
    call :refresh_environment
    echo Relaunching this script manually is required.
    pause
    exit /b 0
) else (
    echo PowerShell 7 is already installed.
)

:: Verify pwsh is available
pwsh -Version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: PowerShell 7 ^(pwsh^) is not available in PATH.
    echo Refreshing environment variables...
    call :refresh_environment
    
    :: Try again after refresh
    pwsh -Version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: PowerShell 7 ^(pwsh^) is still not available.
        echo Please restart your command prompt or system and try again.
        pause
        exit /b 1
    )
)

echo PowerShell 7 verification: PASSED
echo.

:: Check for example/default configuration values
call :check_configuration
if errorlevel 1 goto configuration_error

:menu
echo Select an option:
echo 1. Store current IP address (IPv4 only)
echo 2. Store current IP address (IPv6 only)
echo 3. Store current IP address (Both IPv4 and IPv6)
echo 4. Retrieve stored IP address (IPv4 only)
echo 5. Retrieve stored IP address (IPv6 only)
echo 6. Retrieve stored IP address (Both IPv4 and IPv6)
echo 7. Test network connectivity
echo 8. Exit
echo.
set /p choice="Enter your choice (1-8): "

if "%choice%"=="1" goto store_ipv4
if "%choice%"=="2" goto store_ipv6
if "%choice%"=="3" goto store_both
if "%choice%"=="4" goto retrieve_ipv4
if "%choice%"=="5" goto retrieve_ipv6
if "%choice%"=="6" goto retrieve_both
if "%choice%"=="7" goto test_connectivity
if "%choice%"=="8" goto exit
echo Invalid choice. Please try again.
echo.
goto menu

:store_ipv4
echo.
echo Storing current IPv4 address...
pwsh -ExecutionPolicy Bypass -File "%~dp0get.ps1" -CloudflareApiToken "%CLOUDFLARE_TOKEN%" -Domain "%DOMAIN%" -Subdomain "%SUBDOMAIN%" -IPVersion "v4"
echo.
pause
goto menu

:store_ipv6
echo.
echo Storing current IPv6 address...
pwsh -ExecutionPolicy Bypass -File "%~dp0get.ps1" -CloudflareApiToken "%CLOUDFLARE_TOKEN%" -Domain "%DOMAIN%" -Subdomain "%SUBDOMAIN%" -IPVersion "v6"
echo.
pause
goto menu

:store_both
echo.
echo Storing both IPv4 and IPv6 addresses...
pwsh -ExecutionPolicy Bypass -File "%~dp0get.ps1" -CloudflareApiToken "%CLOUDFLARE_TOKEN%" -Domain "%DOMAIN%" -Subdomain "%SUBDOMAIN%" -IPVersion "both"
echo.
pause
goto menu

:retrieve_ipv4
echo.
echo Retrieving stored IPv4 address...
pwsh -ExecutionPolicy Bypass -File "%~dp0push.ps1" -CloudflareApiToken "%CLOUDFLARE_TOKEN%" -Domain "%DOMAIN%" -Subdomain "%SUBDOMAIN%" -IPVersion "v4"
echo.
pause
goto menu

:retrieve_ipv6
echo.
echo Retrieving stored IPv6 address...
pwsh -ExecutionPolicy Bypass -File "%~dp0push.ps1" -CloudflareApiToken "%CLOUDFLARE_TOKEN%" -Domain "%DOMAIN%" -Subdomain "%SUBDOMAIN%" -IPVersion "v6"
echo.
pause
goto menu

:retrieve_both
echo.
echo Retrieving both stored addresses...
pwsh -ExecutionPolicy Bypass -File "%~dp0push.ps1" -CloudflareApiToken "%CLOUDFLARE_TOKEN%" -Domain "%DOMAIN%" -Subdomain "%SUBDOMAIN%" -IPVersion "both"
echo.
pause
goto menu

:test_connectivity
echo.
echo Testing network connectivity and Cloudflare API access...
pwsh -ExecutionPolicy Bypass -Command "& { . '%~dp0CloudflareHelpers.ps1'; $result = Test-NetworkConnectivity -CurlPath '%~dp0curl\curl.exe'; Write-Host ''; Write-Host 'Testing Cloudflare setup with network test...'; $cfResult = Test-CloudflareSetup -ApiToken '%CLOUDFLARE_TOKEN%' -Domain '%DOMAIN%' -CurlPath '%~dp0curl\curl.exe' -IncludeNetworkTest }"
echo.
pause
goto menu

:exit
echo Goodbye!
exit /b 0

:check_configuration
:: Check if any configuration values contain "example"
echo %CLOUDFLARE_TOKEN% | findstr /I "example" >nul
if not errorlevel 1 (
    echo ERROR: CLOUDFLARE_TOKEN contains example values!
    exit /b 1
)

echo %DOMAIN% | findstr /I "example" >nul
if not errorlevel 1 (
    echo ERROR: DOMAIN contains example values!
    exit /b 1
)

echo %SUBDOMAIN% | findstr /I "example" >nul
if not errorlevel 1 (
    echo ERROR: SUBDOMAIN contains example values!
    exit /b 1
)

:: Check for completely empty values
if "%CLOUDFLARE_TOKEN%"=="" (
    echo ERROR: CLOUDFLARE_TOKEN is empty!
    exit /b 1
)

if "%DOMAIN%"=="" (
    echo ERROR: DOMAIN is empty!
    exit /b 1
)

if "%SUBDOMAIN%"=="" (
    echo ERROR: SUBDOMAIN is empty!
    exit /b 1
)

echo Configuration validation: PASSED
echo.
exit /b 0

:refresh_environment
REM Simple environment refresh - updates PATH from registry
echo | set /p dummy="Refreshing environment variables from registry... "

REM Get system PATH
for /f "usebackq skip=2 tokens=3*" %%A in (`reg query "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul`) do set "SysPath=%%A %%B"

REM Get user PATH  
for /f "usebackq skip=2 tokens=3*" %%A in (`reg query "HKCU\Environment" /v Path 2^>nul`) do set "UserPath=%%A %%B"

REM Combine and set PATH
if defined SysPath if defined UserPath (
    set "PATH=%SysPath%;%UserPath%"
) else if defined SysPath (
    set "PATH=%SysPath%"
) else if defined UserPath (
    set "PATH=%UserPath%"
)

echo Finished.
goto :EOF

:configuration_error
echo.
echo ==========================================
echo           CONFIGURATION ERROR
echo ==========================================
echo.
echo Please edit the configuration section at the top of run.bat
echo and replace the example values with your actual settings:
echo.
echo 1. CLOUDFLARE_TOKEN - Your Cloudflare API token
echo 2. DOMAIN - Your domain name (e.g., mydomain.com)
echo 3. SUBDOMAIN - Your subdomain (e.g., myip)
echo.
echo Example:
echo   set CLOUDFLARE_TOKEN=your_actual_cloudflare_token_here
echo   set DOMAIN=yourdomain.com
echo   set SUBDOMAIN=myip
echo.
echo After editing, save the file and run this script again.
echo ==========================================
echo.
pause
exit /b 1