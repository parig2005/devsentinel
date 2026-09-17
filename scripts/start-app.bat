@echo off
REM ==========================================================================
REM  DevSentinel - start the Spring Boot application (Windows)
REM  Run this in a SECOND terminal window.
REM ==========================================================================

cd /d "%~dp0\.."

echo ============================================
echo  DevSentinel - Spring Boot
echo ============================================
echo.
echo [info] Database: H2 file at .\data\devsentinel.mv.db (created automatically)
echo [info] Once started, open http://localhost:8080
echo.

call mvn spring-boot:run
if errorlevel 1 (
    echo.
    echo [ERROR] Startup failed. Common causes:
    echo   - Maven is not on your PATH        ^(run: mvn -version^)
    echo   - JDK 17+ is not installed         ^(run: java -version^)
    echo   - Port 8080 is already in use      ^(set SERVER_PORT=8081^)
    pause
)
