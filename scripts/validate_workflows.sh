#!/bin/bash

# DevDocs Pro - Workflow Validation Script
# This script validates all GitHub Actions workflows locally

set -e

echo "🚀 DevDocs Pro - Workflow Validation"
echo "===================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success_count=0
total_checks=0

check_result() {
    total_checks=$((total_checks + 1))
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ $2${NC}"
        success_count=$((success_count + 1))
    else
        echo -e "${RED}❌ $2${NC}"
    fi
}

echo "1. 🔍 Checking workflow file existence..."
required_workflows=(
    ".github/workflows/ci.yml"
    ".github/workflows/security-ci.yml"
    ".github/workflows/validate-workflows.yml"
)

for workflow in "${required_workflows[@]}"; do
    if [ -f "$workflow" ]; then
        check_result 0 "$workflow exists"
    else
        check_result 1 "$workflow missing"
    fi
done

echo ""
echo "2. 🔍 Validating CI workflow structure..."
required_jobs=("test" "security-validation" "ai-integration-test" "workflow-summary")

for job in "${required_jobs[@]}"; do
    if grep -q "$job:" .github/workflows/ci.yml; then
        check_result 0 "CI job '$job' found"
    else
        check_result 1 "CI job '$job' missing"
    fi
done

echo ""
echo "3. 🔍 Validating Security CI workflow structure..."
security_jobs=("security-audit" "security-tests" "vulnerability-scan" "compliance-check")

for job in "${security_jobs[@]}"; do
    if grep -q "$job:" .github/workflows/security-ci.yml; then
        check_result 0 "Security job '$job' found"
    else
        check_result 1 "Security job '$job' missing"
    fi
done

echo ""
echo "4. 🔍 Checking environment variables..."
required_env_vars=("JWT_SECRET" "DEVDOCS_MASTER_KEY" "GEMINI_API_KEY")

for var in "${required_env_vars[@]}"; do
    if grep -q "$var" .github/workflows/ci.yml; then
        check_result 0 "Environment variable '$var' found in CI"
    else
        check_result 1 "Environment variable '$var' missing from CI"
    fi
done

echo ""
echo "5. 🔍 Validating workflow triggers..."
if grep -q "on:" .github/workflows/ci.yml && \
   grep -q "push:" .github/workflows/ci.yml && \
   grep -q "pull_request:" .github/workflows/ci.yml; then
    check_result 0 "CI workflow has proper triggers"
else
    check_result 1 "CI workflow missing required triggers"
fi

if grep -q "schedule:" .github/workflows/security-ci.yml; then
    check_result 0 "Security CI has scheduled trigger"
else
    check_result 1 "Security CI missing scheduled trigger"
fi

echo ""
echo "6. 🔍 Running ActionLint validation..."
if command -v actionlint >/dev/null 2>&1; then
    if actionlint -color; then
        check_result 0 "ActionLint validation passed"
    else
        check_result 1 "ActionLint validation failed"
    fi
else
    echo -e "${YELLOW}⚠️  ActionLint not installed, downloading...${NC}"
    if bash <(curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash); then
        if ./actionlint -color; then
            check_result 0 "ActionLint validation passed"
        else
            check_result 1 "ActionLint validation failed"
        fi
    else
        check_result 1 "Failed to install ActionLint"
    fi
fi

echo ""
echo "7. 🔍 Checking YAML syntax..."
yaml_valid=true

for workflow in .github/workflows/*.yml; do
    # Basic YAML syntax check using Python
    if python3 -c "import yaml; yaml.safe_load(open('$workflow'))" 2>/dev/null; then
        check_result 0 "$(basename $workflow) has valid YAML syntax"
    else
        check_result 1 "$(basename $workflow) has invalid YAML syntax"
        yaml_valid=false
    fi
done

echo ""
echo "8. 🔍 Checking workflow dependencies..."
# Check for required GitHub Actions
required_actions=("actions/checkout@v4" "actions/cache@v4" "actions/upload-artifact@v4")

for action in "${required_actions[@]}"; do
    if grep -r "$action" .github/workflows/; then
        check_result 0 "Required action '$action' found"
    else
        check_result 1 "Required action '$action' missing"
    fi
done

echo ""
echo "📊 Validation Summary"
echo "===================="
echo -e "Total checks: $total_checks"
echo -e "Passed: ${GREEN}$success_count${NC}"
echo -e "Failed: ${RED}$((total_checks - success_count))${NC}"

if [ $success_count -eq $total_checks ]; then
    echo ""
    echo -e "${GREEN}🎉 All workflow validations passed!${NC}"
    echo -e "${GREEN}Your GitHub Actions workflows are ready for production.${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}❌ Some workflow validations failed!${NC}"
    echo -e "${RED}Please fix the issues above before deploying.${NC}"
    exit 1
fi
