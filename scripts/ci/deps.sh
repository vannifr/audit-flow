#!/bin/sh
exec sh "$(dirname "$0")/gate.sh" npm 'dependency audit (production, high+)' -- npm audit --omit=dev --audit-level=high
