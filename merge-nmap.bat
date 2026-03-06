@echo off
setlocal enabledelayedexpansion
REM nmap-merge.bat — Generate a NetIntel manifest and produce one HTML report
REM
REM Usage:
REM   nmap-merge.bat scan1.xml scan2.xml ...
REM   (produces report.html in current directory)
REM
REM Or generate manifest only:
REM   nmap-merge.bat --manifest scan1.xml scan2.xml ... > scans.xml
REM   xsltproc nmap-intel.xsl scans.xml > report.html

if "%~1"=="" (
    echo Usage: %~nx0 [--manifest] file1.xml [file2.xml ...]
    echo.
    echo   --manifest   Output manifest XML to stdout instead of generating report
    echo   Without flag: generates report.html using xsltproc
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"
set "MANIFEST_ONLY=0"
set "MANIFEST=%TEMP%\nmap-manifest-%RANDOM%.xml"

if "%~1"=="--manifest" (
    set "MANIFEST_ONLY=1"
    shift
)

REM Build manifest XML
(
echo ^<?xml version="1.0" encoding="UTF-8"?^>
echo ^<netintel-scans^>
) > "%MANIFEST%"

:loop
if "%~1"=="" goto done
set "FULLPATH=%~f1"
echo   ^<scan file="%FULLPATH%"/^>>> "%MANIFEST%"
shift
goto loop

:done
echo ^</netintel-scans^>>> "%MANIFEST%"

if %MANIFEST_ONLY%==1 (
    type "%MANIFEST%"
    del "%MANIFEST%" 2>nul
    exit /b 0
)

REM Transform with xsltproc
"%SCRIPT_DIR%xsltproc.exe" "%SCRIPT_DIR%nmap-intel.xsl" "%MANIFEST%" > report.html
set "RC=%ERRORLEVEL%"
del "%MANIFEST%" 2>nul

if %RC% neq 0 (
    echo Error: xsltproc failed with exit code %RC%
    exit /b %RC%
)

echo Generated report.html
