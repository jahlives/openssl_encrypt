#!/bin/bash
# Quick test runner for telemetry integration tests

set -e

echo "=========================================="
echo "OpenSSL Encrypt Telemetry Test Suite"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}Error: pytest not found${NC}"
    echo "Install with: pip install pytest pytest-cov pytest-mock requests-mock httpx"
    exit 1
fi

# Parse arguments
RUN_CLIENT=true
RUN_SERVER=true
RUN_E2E=true
RUN_SECURITY=false
COVERAGE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --client-only)
            RUN_SERVER=false
            RUN_E2E=false
            shift
            ;;
        --server-only)
            RUN_CLIENT=false
            RUN_E2E=false
            shift
            ;;
        --e2e-only)
            RUN_CLIENT=false
            RUN_SERVER=false
            shift
            ;;
        --with-security)
            RUN_SECURITY=true
            shift
            ;;
        --coverage)
            COVERAGE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --client-only      Run only client integration tests"
            echo "  --server-only      Run only server integration tests"
            echo "  --e2e-only         Run only end-to-end tests"
            echo "  --with-security    Also run security tests"
            echo "  --coverage         Generate coverage report"
            echo "  --help             Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run with --help for usage"
            exit 1
            ;;
    esac
done

# Coverage options
if [ "$COVERAGE" = true ]; then
    COV_OPTS="--cov=openssl_encrypt.plugins.telemetry --cov=openssl_encrypt.modules.telemetry_filter --cov-report=html --cov-report=term-missing"
else
    COV_OPTS=""
fi

# Run tests
FAILED=0

if [ "$RUN_SECURITY" = true ]; then
    echo -e "${BLUE}Running Security Tests...${NC}"
    if pytest tests/test_telemetry_security.py -v $COV_OPTS; then
        echo -e "${GREEN}✓ Security tests passed${NC}"
    else
        echo -e "${RED}✗ Security tests failed${NC}"
        FAILED=1
    fi
    echo ""
fi

if [ "$RUN_CLIENT" = true ]; then
    echo -e "${BLUE}Running Client Integration Tests...${NC}"
    if pytest tests/integration/test_telemetry_integration.py -v $COV_OPTS; then
        echo -e "${GREEN}✓ Client integration tests passed${NC}"
    else
        echo -e "${RED}✗ Client integration tests failed${NC}"
        FAILED=1
    fi
    echo ""
fi

if [ "$RUN_SERVER" = true ]; then
    echo -e "${BLUE}Running Server Integration Tests...${NC}"
    if pytest server/telemetry-server/tests/test_api_integration.py -v $COV_OPTS; then
        echo -e "${GREEN}✓ Server integration tests passed${NC}"
    else
        echo -e "${RED}✗ Server integration tests failed${NC}"
        FAILED=1
    fi
    echo ""
fi

if [ "$RUN_E2E" = true ]; then
    echo -e "${BLUE}Running End-to-End Tests...${NC}"
    if pytest tests/integration/test_telemetry_e2e.py -v $COV_OPTS; then
        echo -e "${GREEN}✓ End-to-end tests passed${NC}"
    else
        echo -e "${RED}✗ End-to-end tests failed${NC}"
        FAILED=1
    fi
    echo ""
fi

# Summary
echo "=========================================="
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✓${NC}"
else
    echo -e "${RED}Some tests failed ✗${NC}"
fi
echo "=========================================="

if [ "$COVERAGE" = true ]; then
    echo ""
    echo "Coverage report generated: htmlcov/index.html"
fi

exit $FAILED
