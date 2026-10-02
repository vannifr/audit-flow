#!/bin/bash
# Setup script for audit tools
# Run this before using the audit framework

set -e

echo "=== Audit Tools Setup ==="
echo ""

MISSING_TOOLS=()

# Check npm (required for npm audit)
echo -n "Checking npm... "
if command -v npm &> /dev/null; then
  VERSION=$(npm --version)
  echo "✓ found (v$VERSION)"
else
  echo "✗ not found"
  MISSING_TOOLS+=("npm: Install Node.js from https://nodejs.org")
fi

# Check gitleaks (optional - secret scanning)
echo -n "Checking gitleaks... "
if command -v gitleaks &> /dev/null; then
  VERSION=$(gitleaks version 2>&1 | head -1)
  echo "✓ found ($VERSION)"
else
  echo "✗ not found (optional)"
  MISSING_TOOLS+=("gitleaks: go install github.com/gitleaks/gitleaks/v8@latest")
fi

# Check semgrep (optional - SAST)
echo -n "Checking semgrep... "
if command -v semgrep &> /dev/null; then
  VERSION=$(semgrep --version 2>&1 | head -1)
  echo "✓ found (v$VERSION)"
else
  echo "✗ not found (optional)"
  MISSING_TOOLS+=("semgrep: pip install semgrep OR brew install semgrep")
fi

# Check git (required for repo operations)
echo -n "Checking git... "
if command -v git &> /dev/null; then
  VERSION=$(git --version | cut -d' ' -f3)
  echo "✓ found (v$VERSION)"
else
  echo "✗ not found"
  MISSING_TOOLS+=("git: Install from https://git-scm.com")
fi

# Check npx (usually comes with npm)
echo -n "Checking npx... "
if command -v npx &> /dev/null; then
  echo "✓ found"
else
  echo "✗ not found"
  MISSING_TOOLS+=("npx: Comes with npm (install Node.js)")
fi

echo ""
echo "=== Summary ==="

if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
  echo "All tools are installed!"
  exit 0
else
  echo "Missing tools:"
  for tool in "${MISSING_TOOLS[@]}"; do
    echo "  - $tool"
  done
  echo ""
  echo "Optional tools can be skipped - the audit will continue with available tools."
  echo "Required tools (npm, git) must be installed."
  exit 1
fi