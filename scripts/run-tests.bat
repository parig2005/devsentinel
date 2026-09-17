@echo off
REM ==========================================================================
REM  DevSentinel - run both test suites (Windows)
REM ==========================================================================

cd /d "%~dp0\.."

echo ============================================
echo  1/2  Python tests  (ai-engine)
echo ============================================
cd ai-engine
if exist ".venv" (
    call .venv\Scripts\activate.bat
) else (
    echo [warn] No venv found. Run scripts\start-ai-service.bat once first.
)
REM Rule-only mode: the tests must not trigger a 500 MB model download
set DEVSENTINEL_SKIP_MODEL=1
python -m pytest tests/ -v
cd ..

echo.
echo ============================================
echo  2/2  Java tests  (Spring Boot)
echo ============================================
call mvn clean test

pause
