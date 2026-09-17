#!/usr/bin/env bash
# DevSentinel - structure self-check (macOS / Linux)
# Run this BEFORE "mvn test" or "mvn spring-boot:run" if either fails.

cd "$(dirname "$0")/.."
FAIL=0

echo "============================================"
echo " DevSentinel structure check"
echo " Running from: $(pwd)"
echo "============================================"
echo

check() {
    if [ -e "$1" ]; then
        echo "[OK]   $1"
    else
        echo "[FAIL] $1 NOT FOUND"
        FAIL=1
    fi
}

check "pom.xml"
check "src/main/java/com/devsentinel/DevSentinelApplication.java"
check "src/main/resources/application.properties"
check "src/main/resources/templates/index.html"
check "src/test/java/com/devsentinel"

if grep -q "@SpringBootApplication" src/main/java/com/devsentinel/DevSentinelApplication.java 2>/dev/null; then
    echo "[OK]   @SpringBootApplication annotation present"
else
    echo "[FAIL] @SpringBootApplication annotation missing"
    FAIL=1
fi

TESTCOUNT=$(find src/test/java -name '*Test.java' 2>/dev/null | wc -l)
echo "       $TESTCOUNT *Test.java files found under src/test/java"
[ "$TESTCOUNT" -eq 0 ] && { echo "[FAIL] zero test files found"; FAIL=1; }

POMCOUNT=$(find . -name pom.xml 2>/dev/null | wc -l)
echo
echo "=== pom.xml count under $(pwd): $POMCOUNT ==="
if [ "$POMCOUNT" -gt 1 ]; then
    echo "[WARN] multiple pom.xml files found:"
    find . -name pom.xml
fi

MAINCOUNT=$(grep -rl "static void main" src/main/java 2>/dev/null | wc -l)
echo
echo "=== main() methods under src/main/java: $MAINCOUNT ==="
if [ "$MAINCOUNT" -gt 1 ]; then
    echo "[FAIL] more than one main() method — this causes"
    echo "       'Unable to find a suitable main class'"
    grep -rl "static void main" src/main/java
    FAIL=1
fi

echo
echo "============================================"
if [ "$FAIL" -eq 0 ]; then
    echo " RESULT: Structure looks correct."
    echo " You can now run:  mvn clean test"
    echo " Then:              mvn spring-boot:run"
else
    echo " RESULT: Problems found above — fix these before running Maven."
fi
echo "============================================"
