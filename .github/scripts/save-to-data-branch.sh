#!/usr/bin/env bash
# Commit the files in $2 to the `data` branch (created on first use) and push it.
# Usage: save-to-data-branch.sh "<commit message>" <folder>   needs GITHUB_TOKEN and GITHUB_REPOSITORY (PUSH_URL overrides the target, for tests)
set -euo pipefail
message="$1"
source_dir="$2"

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

if git ls-remote --exit-code --heads origin data > /dev/null 2>&1; then
  git fetch --depth 1 origin data
  git checkout --quiet -B data FETCH_HEAD
else
  git switch --quiet --orphan data
  git rm -rf --quiet --ignore-unmatch .
fi

cp -r "$source_dir"/. .
git add -A
if git diff --cached --quiet; then
  echo "Nothing new to save."
  exit 0
fi
git commit --quiet -m "$message"
git push "${PUSH_URL:-https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git}" HEAD:data
