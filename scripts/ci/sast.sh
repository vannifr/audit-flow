#!/bin/sh
export EIO_BACKEND="${EIO_BACKEND:-posix}"
exec sh "$(dirname "$0")/gate.sh" semgrep 'SAST' -- semgrep --config=p/security-audit --config=p/typescript --config=p/sql-injection --error --quiet .
