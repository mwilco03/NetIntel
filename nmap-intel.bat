@echo off
setlocal enabledelayedexpansion
REM nmap-intel — Generate a Network Intelligence Report from one or more nmap XML files
REM
REM Usage:
REM   nmap-intel scan.xml > report.html
REM   nmap-intel *.xml > report.html
REM   nmap-intel --classification SECRET --classification-color "#c8102e" *.xml > report.html

set "SCRIPT_DIR=%~dp0"
set "XSL=%SCRIPT_DIR%nmap-intel.xsl"
set "XSLTPROC=%SCRIPT_DIR%xsltproc.exe"
set "XSLT_PARAMS="
set "FILES="
set "COUNT=0"

if not exist "%XSLTPROC%" (
    where xsltproc >nul 2>&1
    if errorlevel 1 (
        echo Error: xsltproc.exe not found >&2
        exit /b 1
    )
    set "XSLTPROC=xsltproc"
)

:parse_args
if "%~1"=="" goto check_files
if "%~1"=="--classification" (
    set "XSLT_PARAMS=!XSLT_PARAMS! --stringparam classification %~2"
    shift & shift
    goto parse_args
)
if "%~1"=="--classification-color" (
    set "XSLT_PARAMS=!XSLT_PARAMS! --stringparam classification-color %~2"
    shift & shift
    goto parse_args
)
set /a COUNT+=1
set "FILES=!FILES! %~1"
set "FILE_!COUNT!=%~f1"
shift
goto parse_args

:check_files
if %COUNT%==0 (
    echo Usage: nmap-intel [OPTIONS] file1.xml [file2.xml ...] ^> report.html >&2
    echo. >&2
    echo Options: >&2
    echo   --classification TEXT     Banner text >&2
    echo   --classification-color    Banner color >&2
    exit /b 1
)

REM Single file: pass directly
if %COUNT%==1 (
    "%XSLTPROC%" %XSLT_PARAMS% "%XSL%" "!FILE_1!"
    exit /b !ERRORLEVEL!
)

REM Multiple files: generate manifest
set "MANIFEST=%TEMP%\nmap-intel-%RANDOM%.xml"

(
echo ^<?xml version="1.0" encoding="UTF-8"?^>
echo ^<netintel-scans^>
) > "%MANIFEST%"

for /L %%i in (1,1,%COUNT%) do (
    echo   ^<scan file="!FILE_%%i!"/^>>> "%MANIFEST%"
)

echo ^</netintel-scans^>>> "%MANIFEST%"

"%XSLTPROC%" %XSLT_PARAMS% "%XSL%" "%MANIFEST%"
set "RC=!ERRORLEVEL!"
del "%MANIFEST%" 2>nul
exit /b %RC%
