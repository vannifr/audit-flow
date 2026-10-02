#!/bin/sh
exec sh "$(dirname "$0")/gate.sh" gitleaks 'secret scan' -- gitleaks dir --no-banner --redact=50 --exit-code 1 --gitleaks-ignore-path .gitleaksignore .
