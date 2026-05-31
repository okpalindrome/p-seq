@echo off
setlocal
cd /d "%~dp0"

set "VENV_PY=.venv\Scripts\python.exe"

if not exist "%VENV_PY%" (
    python -m venv .venv
    if not exist "%VENV_PY%" (
        echo Failed to create virtualenv. Make sure Python 3 is installed and on PATH ^(try: python --version^).
        exit /b 1
    )
    "%VENV_PY%" -m pip install --upgrade pip
    "%VENV_PY%" -m pip install -r requirements.txt
)

"%VENV_PY%" -m backend.app
