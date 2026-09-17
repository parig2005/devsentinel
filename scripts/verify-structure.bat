@echo off
REM ==========================================================================
REM  DevSentinel - structure self-check (Windows)
REM
REM  Run this BEFORE "mvn test" or "mvn spring-boot:run", especially if you
REM  hit "No tests to run" or "Unable to find a suitable main class". It
REM  checks the actual files on YOUR disk and tells you exactly what is
REM  missing or in the wrong place, instead of guessing from an error message.
REM ==========================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0\.."
set FAIL=0

echo ============================================
echo  DevSentinel structure check
echo  Running from: %cd%
echo ============================================
echo.

if exist "pom.xml" (
    echo [OK]   pom.xml found at project root
) else (
    echo [FAIL] pom.xml NOT found in %cd%
    echo        You are probably in the wrong directory, or extracted the
    echo        ZIP so that "devsentinel" is nested one level deeper than
    echo        you think. Look for a "pom.xml" file and cd into that folder.
    set FAIL=1
)

if exist "src\main\java\com\devsentinel\DevSentinelApplication.java" (
    echo [OK]   Main class found: src\main\java\com\devsentinel\DevSentinelApplication.java
) else (
    echo [FAIL] Main class NOT found at src\main\java\com\devsentinel\DevSentinelApplication.java
    set FAIL=1
)

findstr /C:"@SpringBootApplication" "src\main\java\com\devsentinel\DevSentinelApplication.java" >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK]   @SpringBootApplication annotation present
) else (
    echo [FAIL] @SpringBootApplication annotation missing or file unreadable
    set FAIL=1
)

if exist "src\test\java\com\devsentinel" (
    set /a COUNT=0
    for /r "src\test\java\com\devsentinel" %%f in (*Test.java) do set /a COUNT+=1
    echo [OK]   src\test\java\com\devsentinel exists, !COUNT! *Test.java files found
    if !COUNT! equ 0 (
        echo [FAIL] but zero *Test.java files were found inside it
        set FAIL=1
    )
) else (
    echo [FAIL] src\test\java\com\devsentinel does NOT exist
    set FAIL=1
)

if exist "src\main\resources\application.properties" (
    echo [OK]   application.properties found
) else (
    echo [FAIL] src\main\resources\application.properties NOT found
    set FAIL=1
)

if exist "src\main\resources\templates\index.html" (
    echo [OK]   Thymeleaf templates found
) else (
    echo [FAIL] src\main\resources\templates\index.html NOT found
    set FAIL=1
)

echo.
echo === Duplicate / stray pom.xml check ===
set POMCOUNT=0
for /r "%cd%" %%f in (pom.xml) do set /a POMCOUNT+=1
echo    %POMCOUNT% pom.xml file(s) found under %cd%
if %POMCOUNT% gtr 1 (
    echo [WARN] More than one pom.xml exists under this folder. If you merged
    echo        an old copy of this project with a new one, Maven may be
    echo        confused about which module it is building. List them:
    for /r "%cd%" %%f in (pom.xml) do echo        %%f
)

echo.
echo === Duplicate main-method check ===
set MAINCOUNT=0
for /r "src\main\java" %%f in (*.java) do (
    findstr /C:"static void main" "%%f" >nul 2>&1
    if !errorlevel! equ 0 (
        set /a MAINCOUNT+=1
        echo    main^(^) found in: %%f
    )
)
if !MAINCOUNT! gtr 1 (
    echo [FAIL] More than one main^(^) method exists under src\main\java.
    echo        This is exactly what causes "Unable to find a suitable main class".
    set FAIL=1
) else (
    echo [OK]   Exactly one main^(^) method under src\main\java
)

echo.
echo ============================================
if %FAIL% equ 0 (
    echo  RESULT: Structure looks correct.
    echo  You can now run:  mvn clean test
    echo  Then:              mvn spring-boot:run
) else (
    echo  RESULT: Problems found above. Fix those before running Maven -
    echo  the errors you saw from Maven are a downstream symptom of one of
    echo  these structural issues, not a Maven bug.
)
echo ============================================
pause
