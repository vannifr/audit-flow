#!/bin/sh
exec sh "$(dirname "$0")/gate.sh" gitleaks 'staged secret scan' -- gitleaks git --staged --no-banner --redact=50 --exit-code 1 .
