#!/usr/bin/env bash
# Publish this repository to GitHub. Run on YOUR machine (this repo was authored offline).
# Requirements: git, GitHub CLI (`gh auth login` done).
set -euo pipefail

ORG="${1:?usage: scripts/publish.sh <github-org-or-user> [repo-name] }"
REPO="${2:-praxis}"

[ -d .git ] || { git init -b main; }
git add -A
git -c user.name="${GIT_AUTHOR_NAME:-Praxis Maintainers}" -c user.email="${GIT_AUTHOR_EMAIL:-maintainers@example.org}" \
  commit -s -m "docs: initial design, normative spec v0.1-draft, governance, implementation plan" || true

gh repo create "$ORG/$REPO" --public --source=. --remote=origin --push \
  --description "Praxis: the open protocol for capturing, verifying, and transmitting expert judgment" \
  --homepage "https://github.com/$ORG/$REPO"

gh repo edit "$ORG/$REPO" --enable-discussions --enable-issues \
  --add-topic judgment --add-topic open-protocol --add-topic local-first --add-topic calibration \
  --add-topic decision-making --add-topic ai-agents --add-topic rust

# Recommended protections (adjust to your plan):
gh api -X PUT "repos/$ORG/$REPO/branches/main/protection" \
  -f required_status_checks.strict=true -f 'required_status_checks.contexts[]=ci' \
  -f enforce_admins=true -f required_pull_request_reviews.required_approving_review_count=1 \
  -F restrictions= 2>/dev/null || echo "NOTE: set branch protection manually if your plan doesn't allow API."

echo "Published: https://github.com/$ORG/$REPO"
echo "Next: install the DCO GitHub App, enable private vulnerability reporting, then point your AI agent at AGENTS.md."
