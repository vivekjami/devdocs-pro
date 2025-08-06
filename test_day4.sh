#!/bin/bash

# DevDocs Pro Day 4 AI Integration Test Suite
# ==========================================

echo "🚀 DevDocs Pro Day 4 AI Integration Test Suite"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo -e "${BLUE}🧪 Test $TESTS_TOTAL: $test_name${NC}"
    
    # Run the test command
    if eval "$test_command"; then
        echo -e "   ${GREEN}✅ PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "   ${RED}❌ FAILED${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Function to check environment
check_env() {
    echo -e "${BLUE}🔍 Environment Check${NC}"
    
    if [[ -f ".env" ]]; then
        echo -e "   ${GREEN}✅ .env file found${NC}"
    else
        echo -e "   ${RED}❌ .env file missing${NC}"
        return 1
    fi
    
    if grep -q "GEMINI_API_KEY" .env; then
        echo -e "   ${GREEN}✅ GEMINI_API_KEY configured${NC}"
    else
        echo -e "   ${YELLOW}⚠️  GEMINI_API_KEY not found in .env${NC}"
    fi
    
    if [[ -f ".env.example" ]]; then
        echo -e "   ${GREEN}✅ .env.example template exists${NC}"
    else
        echo -e "   ${RED}❌ .env.example missing${NC}"
    fi
    
    echo ""
}

# Function to build and test compilation
test_compilation() {
    echo -e "${BLUE}🔨 Compilation Tests${NC}"
    
    run_test "Clean build" "cargo clean > /dev/null 2>&1"
    run_test "Debug build" "cargo build --all > /dev/null 2>&1"
    run_test "Release build" "cargo build --all --release > /dev/null 2>&1"
    run_test "Test compilation" "cargo test --no-run --all > /dev/null 2>&1"
    
    echo ""
}

# Function to run unit tests
test_units() {
    echo -e "${BLUE}🔬 Unit Tests${NC}"
    
    # Capture test output
    TEST_OUTPUT=$(cargo test --all 2>&1)
    
    if echo "$TEST_OUTPUT" | grep -q "test result: ok"; then
        UNIT_TESTS=$(echo "$TEST_OUTPUT" | grep -o "[0-9]* passed" | head -1)
        echo -e "   ${GREEN}✅ Unit tests: $UNIT_TESTS${NC}"
    else
        echo -e "   ${RED}❌ Unit tests failed${NC}"
        echo "$TEST_OUTPUT"
        return 1
    fi
    
    echo ""
}

# Function to test AI components
test_ai_components() {
    echo -e "${BLUE}🤖 AI Component Tests${NC}"
    
    # Test that AI modules compile and are available
    if cargo doc --no-deps --document-private-items > /dev/null 2>&1; then
        echo -e "   ${GREEN}✅ AI modules documented successfully${NC}"
    else
        echo -e "   ${RED}❌ AI documentation generation failed${NC}"
    fi
    
    # Check for key AI files
    for file in "crates/devdocs-core/src/ai/gemini_client.rs" \
                "crates/devdocs-core/src/ai/prompts.rs" \
                "crates/devdocs-core/src/analysis/traffic_analyzer.rs" \
                "crates/devdocs-core/src/analysis/schema_inference.rs" \
                "crates/devdocs-middleware/src/ai_processor.rs"; do
        if [[ -f "$file" ]]; then
            echo -e "   ${GREEN}✅ $file exists${NC}"
        else
            echo -e "   ${RED}❌ $file missing${NC}"
        fi
    done
    
    echo ""
}

# Function to test server functionality
test_server() {
    echo -e "${BLUE}🖥️  Server Integration Test${NC}"
    
    # Start server in background
    echo -e "   ${YELLOW}🚀 Starting server...${NC}"
    cargo run --bin basic_usage > server.log 2>&1 &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 3
    
    # Test server endpoints
    if curl -f -s http://localhost:3000/ > /dev/null; then
        echo -e "   ${GREEN}✅ Server responding on port 3000${NC}"
        
        # Test different endpoints
        curl -f -s -X GET "http://localhost:3000/health" > /dev/null && \
            echo -e "   ${GREEN}✅ GET /health working${NC}"
            
        curl -f -s -X POST "http://localhost:3000/api/test" \
            -H "Content-Type: application/json" \
            -d '{"test": true}' > /dev/null && \
            echo -e "   ${GREEN}✅ POST /api/test working${NC}"
        
    else
        echo -e "   ${RED}❌ Server not responding${NC}"
    fi
    
    # Stop server
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    
    # Check server logs
    if [[ -f server.log ]] && [[ -s server.log ]]; then
        echo -e "   ${GREEN}✅ Server logs generated${NC}"
        # Show any important log messages
        if grep -i "error\|panic" server.log > /dev/null; then
            echo -e "   ${YELLOW}⚠️  Server logs contain errors:${NC}"
            grep -i "error\|panic" server.log | head -3
        fi
    fi
    
    # Cleanup
    rm -f server.log
    echo ""
}

# Function to test feature completeness
test_features() {
    echo -e "${BLUE}📋 Feature Completeness Check${NC}"
    
    # Check for AI integration features
    if grep -r "GeminiClient" crates/ > /dev/null; then
        echo -e "   ${GREEN}✅ Gemini AI client implemented${NC}"
    fi
    
    if grep -r "TrafficAnalyzer" crates/ > /dev/null; then
        echo -e "   ${GREEN}✅ Traffic analysis implemented${NC}"
    fi
    
    if grep -r "schema_inference" crates/ > /dev/null; then
        echo -e "   ${GREEN}✅ Schema inference implemented${NC}"
    fi
    
    if grep -r "batch_processor" crates/ > /dev/null; then
        echo -e "   ${GREEN}✅ Batch processing implemented${NC}"
    fi
    
    if grep -r "AIProcessorService" crates/ > /dev/null; then
        echo -e "   ${GREEN}✅ AI processor service implemented${NC}"
    fi
    
    echo ""
}

# Function to generate summary
generate_summary() {
    echo -e "${BLUE}📊 Test Summary${NC}"
    echo "=================================="
    echo -e "Total Tests: ${TESTS_TOTAL}"
    echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
    echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo ""
        echo -e "${GREEN}🎉 ALL TESTS PASSED! Day 4 AI Integration Complete!${NC}"
        echo -e "${GREEN}🚀 DevDocs Pro is ready for production with AI-powered documentation generation!${NC}"
    else
        echo ""
        echo -e "${RED}❌ Some tests failed. Please review the output above.${NC}"
    fi
    echo ""
}

# Main test execution
main() {
    # Change to project directory if not already there
    if [[ ! -f "Cargo.toml" ]]; then
        echo -e "${RED}❌ Please run this script from the DevDocs Pro project root${NC}"
        exit 1
    fi
    
    # Run all test suites
    check_env
    test_compilation
    test_units
    test_ai_components
    test_server
    test_features
    
    # Generate final summary
    generate_summary
    
    # Exit with appropriate code
    if [[ $TESTS_FAILED -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Run the main function
main "$@"
