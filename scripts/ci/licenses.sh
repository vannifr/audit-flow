#!/bin/sh
exec sh "$(dirname "$0")/gate.sh" npx 'license check' -- npx -y license-checker@25 --summary --failOn 'GPL;AGPL'
