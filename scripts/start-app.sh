#!/usr/bin/env bash
# DevSentinel - start the Spring Boot application (macOS / Linux)
set -e
cd "$(dirname "$0")/.."
echo "[info] Open http://localhost:8080 once startup finishes."
exec mvn spring-boot:run
