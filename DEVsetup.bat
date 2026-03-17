@echo off
title Sirius Vault DEV Setup
color 0A

echo ===================================================
echo           SIRIUS VAULT - DEV SETUP
echo ===================================================
echo.

:: 1. Python Version Check
echo [1/4] Checking Python installation...
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not added to PATH!
    echo Opening Python download page...
    timeout /t 3 >nul
    start https://www.python.org/downloads/windows/
    echo ==============================================================
    echo ⚠️ CRITICAL WARNING:
    echo Please DO NOT download the absolute latest version!
    echo Our GUI framework (PyQt6) works best with Python 3.12.
    echo Please scroll down and download a "Python 3.12.x" installer.
    echo.
    echo IMPORTANT: Check the "Add Python to PATH" box during installation!
    echo ==============================================================
    pause
    exit /b
)

echo.
echo Python is installed. Current version:
python --version
echo ==============================================================
echo ⚠️ WARNING: Please ensure your Python version is 3.12.x!
echo Our GUI framework (PyQt6) works best with Python 3.12.
echo If your version is different, the installation might fail.
echo Press Ctrl+C to cancel setup and install Python 3.12 if needed.
echo Otherwise, press any key to continue...
echo ==============================================================
pause

echo.
echo Moving on...
echo.

:: 2. Creating Venv 
echo [2/4] Creating virtual environment (venv)...
IF EXIST venv (
    echo Virtual environment already exists. Skipping creation...
) ELSE (
    py -3.12 -m venv venv
    echo venv created successfully.
)
echo.

:: 3. Venv Activation and Preparing Libraries
echo [3/4] Activating venv and installing requirements...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
echo.

:: 4. Creating Shortcut for easy launch
echo [4/4] Creating 'start_app.bat' for easy launch...
echo @echo off > start_app.bat
echo call venv\Scripts\activate.bat >> start_app.bat
echo python main.py >> start_app.bat
echo exit >> start_app.bat

echo ===================================================
echo SETUP COMPLETE!
echo You can now double-click 'start_app.bat' to run Sirius Vault.
echo ===================================================
pause