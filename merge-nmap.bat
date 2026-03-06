@echo off
setlocal enabledelayedexpansion
REM merge-nmap.bat — Merge multiple nmap XML files and generate one HTML report
REM
REM Usage:
REM   merge-nmap.bat *.xml
REM   (produces report.html in current directory)

if "%~1"=="" (
    echo Usage: %~nx0 file1.xml [file2.xml ...]
    exit /b 1
)

set "FIRST=%~1"
set "MERGED=%TEMP%\nmap-merged-%RANDOM%.xml"
set "SCRIPT_DIR=%~dp0"
set "COUNT=0"
set "TOTAL_UP=0"
set "TOTAL_DOWN=0"
set "TOTAL_ALL=0"

REM Count files
for %%f in (%*) do set /a COUNT+=1

REM Get attributes from first file
for /f "tokens=*" %%a in ('findstr /r "scanner=" "%FIRST%"') do set "NMAPLINE=%%a"
for /f "tokens=*" %%a in ('findstr /r "startstr=" "%FIRST%"') do set "STARTLINE=%%a"

REM Write header
(
echo ^<?xml version="1.0" encoding="UTF-8"?^>
echo ^<nmaprun scanner="nmap" args="merged: %COUNT% files" start="0" startstr="merged" version="7.95" xmloutputversion="1.05"^>
echo ^<scaninfo type="syn" protocol="tcp" numservices="65535" services="1-65535"/^>
echo ^<verbose level="0"/^>
echo ^<debugging level="0"/^>
) > "%MERGED%"

REM Extract host blocks from each file
for %%f in (%*) do (
    set "INHOST=0"
    for /f "usebackq tokens=* delims=" %%l in ("%%f") do (
        set "LINE=%%l"
        echo !LINE! | findstr /r "<host[ >]" >nul 2>&1 && set "INHOST=1"
        if !INHOST!==1 echo !LINE!>> "%MERGED%"
        echo !LINE! | findstr /r "</host>" >nul 2>&1 && set "INHOST=0"
    )
)

REM Write footer
(
echo ^<runstats^>^<finished time="0" timestr="merged" summary="Merged %COUNT% scans" elapsed="0" exit="success"/^>^<hosts up="0" down="0" total="0"/^>^</runstats^>
echo ^</nmaprun^>
) >> "%MERGED%"

REM Transform
"%SCRIPT_DIR%xsltproc.exe" "%SCRIPT_DIR%nmap-intel.xsl" "%MERGED%" > report.html
del "%MERGED%" 2>nul
echo Generated report.html from %COUNT% scan(s)
