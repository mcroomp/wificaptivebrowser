@echo off
setlocal
pushd "%~dp0" || exit /b 1
where uv >nul 2>nul
if errorlevel 1 set "PATH=%USERPROFILE%\.local\bin;%PATH%"
where uv >nul 2>nul
if errorlevel 1 (
    echo Installing uv for the current user. Internet access is required. >&2
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'Stop'; $env:UV_INSTALL_DIR = Join-Path $env:USERPROFILE '.local\bin'; $env:UV_NO_MODIFY_PATH = '1'; Invoke-RestMethod 'https://astral.sh/uv/install.ps1' | Invoke-Expression"
    if errorlevel 1 goto setup_failed
)
where uv >nul 2>nul
if errorlevel 1 goto setup_failed
echo Checking Python and project dependencies... >&2
call uv sync --frozen
if errorlevel 1 goto setup_failed
call :prepare_browser %*
if errorlevel 1 goto setup_failed
if "%~1"=="" (
    uv run --offline --frozen python -m captive_tracer --browser --platform iphone
) else (
    uv run --offline --frozen python -m captive_tracer --platform windows %*
)
set "result=%errorlevel%"
goto finish
:setup_failed
echo ERROR: Dependency setup failed. Connect to the internet and retry. >&2
set "result=1"
:finish
popd
if "%~1"=="" pause
exit /b %result%

:prepare_browser
set "browser_mode="
set "browser_platform=windows"
set "show_help="
if "%~1"=="" (
    set "browser_mode=1"
    set "browser_platform=iphone"
)
:parse_browser_args
if "%~1"=="" goto install_browser
if /i "%~1"=="--browser" set "browser_mode=1"
if /i "%~1"=="--platform" set "browser_platform=%~2"
if /i "%~1"=="--platform=iphone" set "browser_platform=iphone"
if /i "%~1"=="--platform=windows" set "browser_platform=windows"
if /i "%~1"=="--help" set "show_help=1"
if /i "%~1"=="-h" set "show_help=1"
shift
goto parse_browser_args
:install_browser
if defined show_help exit /b 0
if not defined browser_mode exit /b 0
if /i not "%browser_platform%"=="iphone" exit /b 0
echo Checking the Playwright WebKit browser... >&2
call uv run --offline --frozen playwright install webkit
exit /b %errorlevel%
