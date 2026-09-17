@echo off
REM ==========================================================================
REM  DevSentinel - start the Python AI service (Windows)
REM  Run this in its OWN terminal window and leave it open.
REM ==========================================================================

cd /d "%~dp0\..\ai-engine"

echo ============================================
echo  DevSentinel AI Service
echo ============================================
echo.

REM Create the virtual environment on first run
if not exist ".venv" (
    echo [setup] Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Could not create the venv. Is Python 3.10+ on your PATH?
        pause
        exit /b 1
    )

    echo [setup] Installing dependencies. This can take several minutes.
    call .venv\Scripts\activate.bat
    python -m pip install --upgrade pip
    REM CPU-only torch is a much smaller download than the default CUDA build
    pip install torch --index-url https://download.pytorch.org/whl/cpu
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

echo.
echo [info] Starting on http://localhost:8000
echo [info] First run downloads the CodeBERT model (~500 MB).
echo [info] To skip the download, set DEVSENTINEL_SKIP_MODEL=1 before running.
echo [info] Press Ctrl+C to stop - the Spring app will switch to DEGRADED mode.
echo.

uvicorn main:app --host 127.0.0.1 --port 8000
