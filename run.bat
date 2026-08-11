@echo off
REM Double-click this file on Windows to start the Threat Intelligence System.
cd /d "%~dp0"

REM Prefer the project's virtualenv python; fall back to system python.
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" run.py
) else (
    REM First run with no venv: create it and install everything, then start.
    python run.py --setup
)

echo.
echo The system has stopped. Press any key to close this window.
pause >nul
