@echo off
:: Check if the script is being run as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as administrator.
) else (
    echo Requesting administrator privileges...
    :: Relaunch the script with administrator privileges
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Define the URL of the PowerShell script and the temporary file path
set "ps1_url=https://raw.githubusercontent.com/tut-os/unfk-windows/refs/heads/main/unfk-windows.ps1"
set "temp_ps1=%TEMP%\unfk-windows.ps1"

:: Download the PowerShell script to the TEMP directory
echo Downloading PowerShell script...
powershell -Command "Invoke-WebRequest -Uri '%ps1_url%' -OutFile '%temp_ps1%'"

:: Check if the download was successful
if exist "%temp_ps1%" (
    echo Running the downloaded PowerShell script...
    powershell -ExecutionPolicy Bypass -File "%temp_ps1%"
) else (
    echo Failed to download the PowerShell script.
    pause
    exit /b
)

:: Delete the downloaded PowerShell script
echo Cleaning up...
del "%temp_ps1%"

pause