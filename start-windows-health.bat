@echo off
REM Windows Health & Repair — double-click launcher.
REM Checks for Python, starts the app. The app itself detects whether it
REM has administrator rights and offers a "Relaunch as admin" button —
REM fixes need admin, scanning does not.

title Windows Health & Repair

echo Checking for Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo Python is not installed.
    echo.
    echo Opening the Python download page...
    echo Please install Python, making sure to check
    echo "Add python.exe to PATH" during setup.
    echo.
    echo After installing, double-click this file again.
    echo.
    start https://www.python.org/downloads/windows/
    pause
    exit /b 1
)

echo Python found. Starting Windows Health ^& Repair...
echo.
python "%~dp0windows_health.py"
if %errorlevel% neq 0 (
    echo.
    echo The app exited with an error. See above for details.
    pause
)
