@echo off
setlocal
pushd "%~dp0" || exit /b 1
where uv >nul 2>nul
if errorlevel 1 (
    echo ERROR: uv is not on PATH. Install uv, then run uv sync --frozen here. >&2
    set "result=9009"
    goto finish
)
if "%~1"=="" (
    uv run --offline --frozen python -m captive_tracer --browser --platform iphone
) else (
    uv run --offline --frozen python -m captive_tracer --platform windows %*
)
set "result=%errorlevel%"
:finish
popd
if "%~1"=="" pause
exit /b %result%
