#!/bin/bash
# cleanup_liboqs.sh - Detect and remove liboqs and liboqs-python installations
# Usage: bash cleanup_liboqs.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  liboqs & liboqs-python Cleanup Script${NC}"
echo -e "${BLUE}================================================${NC}\n"

# Arrays to store found items
declare -a LIBOQS_LIBS=()
declare -a LIBOQS_HEADERS=()
declare -a LIBOQS_CMAKE=()
declare -a LIBOQS_PKGCONFIG=()
declare -a LIBOQS_PYTHON=()
NEEDS_SUDO=false

echo -e "${YELLOW}Scanning for liboqs installations...${NC}\n"

# Function to check if file/directory exists and add to array
check_and_add() {
    local path="$1"
    local array_name="$2"

    if [ -e "$path" ]; then
        eval "${array_name}+=(\"$path\")"
        return 0
    fi
    return 1
}

# Search common library locations for liboqs
SEARCH_PATHS=(
    "/usr/local/lib"
    "/usr/local/lib64"
    "/usr/lib"
    "/usr/lib64"
    "$HOME/.local/lib"
    "$HOME/.local/lib64"
    "/opt/liboqs/lib"
    "/opt/liboqs/lib64"
)

echo "Searching for liboqs libraries..."
for path in "${SEARCH_PATHS[@]}"; do
    if [ -d "$path" ]; then
        while IFS= read -r -d '' file; do
            LIBOQS_LIBS+=("$file")
            # Check if we need sudo (anything outside user home)
            if [[ ! "$file" =~ ^"$HOME" ]]; then
                NEEDS_SUDO=true
            fi
        done < <(find "$path" -maxdepth 1 -name "liboqs*" -print0 2>/dev/null)
    fi
done

# Search for header files
HEADER_PATHS=(
    "/usr/local/include/oqs"
    "/usr/include/oqs"
    "$HOME/.local/include/oqs"
    "/opt/liboqs/include/oqs"
)

echo "Searching for liboqs headers..."
for path in "${HEADER_PATHS[@]}"; do
    if [ -d "$path" ]; then
        LIBOQS_HEADERS+=("$path")
        if [[ ! "$path" =~ ^"$HOME" ]]; then
            NEEDS_SUDO=true
        fi
    fi
done

# Search for CMake configuration files
CMAKE_PATHS=(
    "/usr/local/lib/cmake/liboqs"
    "/usr/local/lib64/cmake/liboqs"
    "/usr/lib/cmake/liboqs"
    "/usr/lib64/cmake/liboqs"
    "$HOME/.local/lib/cmake/liboqs"
    "$HOME/.local/lib64/cmake/liboqs"
    "/opt/liboqs/lib/cmake/liboqs"
)

echo "Searching for liboqs CMake configs..."
for path in "${CMAKE_PATHS[@]}"; do
    if [ -d "$path" ]; then
        LIBOQS_CMAKE+=("$path")
        if [[ ! "$path" =~ ^"$HOME" ]]; then
            NEEDS_SUDO=true
        fi
    fi
done

# Search for pkg-config files
PKGCONFIG_PATHS=(
    "/usr/local/lib/pkgconfig/liboqs.pc"
    "/usr/local/lib64/pkgconfig/liboqs.pc"
    "/usr/lib/pkgconfig/liboqs.pc"
    "/usr/lib64/pkgconfig/liboqs.pc"
    "$HOME/.local/lib/pkgconfig/liboqs.pc"
    "$HOME/.local/lib64/pkgconfig/liboqs.pc"
    "/usr/share/pkgconfig/liboqs.pc"
)

echo "Searching for liboqs pkg-config files..."
for path in "${PKGCONFIG_PATHS[@]}"; do
    if [ -f "$path" ]; then
        LIBOQS_PKGCONFIG+=("$path")
        if [[ ! "$path" =~ ^"$HOME" ]]; then
            NEEDS_SUDO=true
        fi
    fi
done

# Check for liboqs-python via pip
echo "Checking for liboqs-python via pip..."
if pip3 show liboqs-python &>/dev/null; then
    LIBOQS_PYTHON_LOCATION=$(pip3 show liboqs-python 2>/dev/null | grep "Location:" | cut -d' ' -f2)
    LIBOQS_PYTHON+=("pip: liboqs-python (installed at: $LIBOQS_PYTHON_LOCATION)")
fi

# Also check in common Python site-packages
PYTHON_PATHS=(
    "$HOME/.local/lib/python*/site-packages/oqs"
    "/usr/local/lib/python*/site-packages/oqs"
    "/usr/lib/python*/site-packages/oqs"
)

for pattern in "${PYTHON_PATHS[@]}"; do
    for path in $pattern; do
        if [ -d "$path" ]; then
            LIBOQS_PYTHON+=("$path")
            if [[ ! "$path" =~ ^"$HOME" ]]; then
                NEEDS_SUDO=true
            fi
        fi
    done
done

# Display findings
echo -e "\n${BLUE}================================================${NC}"
echo -e "${BLUE}  Scan Results${NC}"
echo -e "${BLUE}================================================${NC}\n"

TOTAL_FOUND=0

if [ ${#LIBOQS_LIBS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Found ${#LIBOQS_LIBS[@]} liboqs library file(s):${NC}"
    for item in "${LIBOQS_LIBS[@]}"; do
        echo "  - $item"
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
    done
    echo
fi

if [ ${#LIBOQS_HEADERS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Found ${#LIBOQS_HEADERS[@]} liboqs header directory(ies):${NC}"
    for item in "${LIBOQS_HEADERS[@]}"; do
        echo "  - $item"
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
    done
    echo
fi

if [ ${#LIBOQS_CMAKE[@]} -gt 0 ]; then
    echo -e "${YELLOW}Found ${#LIBOQS_CMAKE[@]} liboqs CMake configuration(s):${NC}"
    for item in "${LIBOQS_CMAKE[@]}"; do
        echo "  - $item"
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
    done
    echo
fi

if [ ${#LIBOQS_PKGCONFIG[@]} -gt 0 ]; then
    echo -e "${YELLOW}Found ${#LIBOQS_PKGCONFIG[@]} liboqs pkg-config file(s):${NC}"
    for item in "${LIBOQS_PKGCONFIG[@]}"; do
        echo "  - $item"
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
    done
    echo
fi

if [ ${#LIBOQS_PYTHON[@]} -gt 0 ]; then
    echo -e "${YELLOW}Found ${#LIBOQS_PYTHON[@]} liboqs-python installation(s):${NC}"
    for item in "${LIBOQS_PYTHON[@]}"; do
        echo "  - $item"
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
    done
    echo
fi

# Check if anything was found
if [ $TOTAL_FOUND -eq 0 ]; then
    echo -e "${GREEN}No liboqs or liboqs-python installations found!${NC}"
    echo -e "${GREEN}Your system is already clean.${NC}"
    exit 0
fi

# Show sudo requirement
if [ "$NEEDS_SUDO" = true ]; then
    echo -e "${RED}⚠ Some files require sudo privileges to remove.${NC}"
    echo -e "${RED}  You will be prompted for your password.${NC}\n"
fi

# Ask for confirmation
echo -e "${BLUE}================================================${NC}"
echo -e "${RED}⚠ WARNING: This will permanently delete all found files!${NC}"
echo -e "${BLUE}================================================${NC}\n"

read -p "Do you want to remove all these files? (yes/no): " -r
echo

if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo -e "${YELLOW}Cleanup cancelled by user.${NC}"
    exit 0
fi

# Perform cleanup
echo -e "${BLUE}Starting cleanup...${NC}\n"

REMOVED_COUNT=0
FAILED_COUNT=0

# Function to remove item
remove_item() {
    local item="$1"
    local use_sudo="$2"

    if [ "$use_sudo" = true ]; then
        if sudo rm -rf "$item" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} Removed: $item"
            REMOVED_COUNT=$((REMOVED_COUNT + 1))
            return 0
        else
            echo -e "  ${RED}✗${NC} Failed to remove: $item"
            FAILED_COUNT=$((FAILED_COUNT + 1))
            return 1
        fi
    else
        if rm -rf "$item" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} Removed: $item"
            REMOVED_COUNT=$((REMOVED_COUNT + 1))
            return 0
        else
            echo -e "  ${RED}✗${NC} Failed to remove: $item"
            FAILED_COUNT=$((FAILED_COUNT + 1))
            return 1
        fi
    fi
}

# Remove liboqs-python first (via pip)
if pip3 show liboqs-python &>/dev/null; then
    echo "Uninstalling liboqs-python via pip..."
    if pip3 uninstall -y liboqs-python &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Uninstalled liboqs-python via pip"
        REMOVED_COUNT=$((REMOVED_COUNT + 1))
    else
        echo -e "  ${RED}✗${NC} Failed to uninstall liboqs-python via pip"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
fi

# Remove Python site-packages (if any remain after pip uninstall)
if [ ${#LIBOQS_PYTHON[@]} -gt 0 ]; then
    echo "Removing liboqs-python directories..."
    for item in "${LIBOQS_PYTHON[@]}"; do
        # Skip the pip: entry
        if [[ "$item" =~ ^pip: ]]; then
            continue
        fi

        if [[ "$item" =~ ^"$HOME" ]]; then
            remove_item "$item" false
        else
            remove_item "$item" true
        fi
    done
fi

# Remove liboqs libraries
if [ ${#LIBOQS_LIBS[@]} -gt 0 ]; then
    echo "Removing liboqs libraries..."
    for item in "${LIBOQS_LIBS[@]}"; do
        if [[ "$item" =~ ^"$HOME" ]]; then
            remove_item "$item" false
        else
            remove_item "$item" true
        fi
    done
fi

# Remove liboqs headers
if [ ${#LIBOQS_HEADERS[@]} -gt 0 ]; then
    echo "Removing liboqs headers..."
    for item in "${LIBOQS_HEADERS[@]}"; do
        if [[ "$item" =~ ^"$HOME" ]]; then
            remove_item "$item" false
        else
            remove_item "$item" true
        fi
    done
fi

# Remove liboqs CMake configs
if [ ${#LIBOQS_CMAKE[@]} -gt 0 ]; then
    echo "Removing liboqs CMake configurations..."
    for item in "${LIBOQS_CMAKE[@]}"; do
        if [[ "$item" =~ ^"$HOME" ]]; then
            remove_item "$item" false
        else
            remove_item "$item" true
        fi
    done
fi

# Remove liboqs pkg-config files
if [ ${#LIBOQS_PKGCONFIG[@]} -gt 0 ]; then
    echo "Removing liboqs pkg-config files..."
    for item in "${LIBOQS_PKGCONFIG[@]}"; do
        if [[ "$item" =~ ^"$HOME" ]]; then
            remove_item "$item" false
        else
            remove_item "$item" true
        fi
    done
fi

# Clear pip cache
echo -e "\nClearing pip cache..."
if pip3 cache remove liboqs-python &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Cleared pip cache for liboqs-python"
else
    echo -e "  ${YELLOW}⚠${NC} No pip cache to clear (or cache clear failed)"
fi

# Summary
echo -e "\n${BLUE}================================================${NC}"
echo -e "${BLUE}  Cleanup Summary${NC}"
echo -e "${BLUE}================================================${NC}\n"

echo -e "${GREEN}Successfully removed: $REMOVED_COUNT item(s)${NC}"
if [ $FAILED_COUNT -gt 0 ]; then
    echo -e "${RED}Failed to remove: $FAILED_COUNT item(s)${NC}"
fi

# Verify cleanup
echo -e "\n${YELLOW}Verifying cleanup...${NC}\n"

VERIFY_OK=true

# Check pkg-config
if pkg-config --exists liboqs 2>/dev/null; then
    echo -e "  ${RED}✗${NC} liboqs still found via pkg-config"
    VERIFY_OK=false
else
    echo -e "  ${GREEN}✓${NC} liboqs not found via pkg-config"
fi

# Check Python import
if python3 -c "import oqs" 2>/dev/null; then
    echo -e "  ${RED}✗${NC} liboqs-python still importable"
    VERIFY_OK=false
else
    echo -e "  ${GREEN}✓${NC} liboqs-python not importable"
fi

# Check pip
if pip3 show liboqs-python &>/dev/null; then
    echo -e "  ${RED}✗${NC} liboqs-python still in pip list"
    VERIFY_OK=false
else
    echo -e "  ${GREEN}✓${NC} liboqs-python not in pip list"
fi

echo

if [ "$VERIFY_OK" = true ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Cleanup completed successfully!${NC}"
    echo -e "${GREEN}========================================${NC}\n"
    echo -e "You can now test the build process from scratch:"
    echo -e "  ${BLUE}cd /home/work/private/git/openssl_encrypt${NC}"
    echo -e "  ${BLUE}pip install -e .${NC}"
    echo
else
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  Cleanup completed with warnings${NC}"
    echo -e "${YELLOW}========================================${NC}\n"
    echo -e "Some items may still exist. Please check manually."
    echo
fi

exit 0
