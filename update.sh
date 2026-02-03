#!/usr/bin/env bash
#
# Update script for r2-automation
# Pushes changes to both GitHub repo and Gist
#
set -euo pipefail

REPO_DIR="/home/ubuntu/.openclaw/workspace/repos/r2-automation"
GIST_ID="8c4b82fba97777854f492abe98498380"

cd "${REPO_DIR}"

echo "=== Updating R2 Automation ==="
echo

# Check for changes
if [[ -z $(git status --porcelain) ]]; then
    echo "No changes to commit"
    exit 0
fi

# Show changes
echo "Changes detected:"
git status --short
echo

# Commit changes
read -p "Enter commit message: " msg
if [[ -z "${msg}" ]]; then
    msg="Update r2-processor.sh $(date +%Y-%m-%d)"
fi

git add -A
git commit -m "${msg}"

# Push to GitHub
echo
echo "Pushing to GitHub repo..."
git push origin master

# Update gist
echo
echo "Updating gist..."
gh gist edit "${GIST_ID}" r2-processor.sh

echo
echo "=== Update complete ==="
echo "Repo: https://github.com/spectre-2b/r2-automation"
echo "Gist: https://gist.github.com/spectre-2b/${GIST_ID}"
