@echo off
REM ---------------------------------------------------------------------------
REM  malscan launcher for Windows (no .exe -> no SmartScreen warning)
REM  Double-click this file, or run it from a terminal.
REM ---------------------------------------------------------------------------
setlocal

REM Prefer the Python launcher, fall back to python on PATH.
where py >nul 2>nul
if %errorlevel%==0 (
    set "PY=py -3"
) else (
    set "PY=python"
)

echo Installing/refreshing dependencies...
%PY% -m pip install -r "%~dp0requirements.txt" flask waitress
if errorlevel 1 (
    echo.
    echo Failed to install dependencies. Make sure Python 3 is installed:
    echo   https://www.python.org/downloads/
    pause
    exit /b 1
)

echo.
echo Starting malscan dashboard at http://127.0.0.1:8080
echo Leave this window open while you use it; close it to quit.
echo.
%PY% "%~dp0serve.py"

pause
endlocal
