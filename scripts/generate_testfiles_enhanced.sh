#!/usr/bin/env bash

# Enhanced script to generate test files with parameters derived from filenames
# Filename format: test_[prefix]_[algo]_[hash1:rounds+hash2:rounds+...]_[kdf1:rounds+kdf2:rounds+...]_[encryption_data].txt
# Examples:
#   test_v5_aes-gcm_sha512:10000+sha256:5000_argon2:10+pbkdf2:100000_standard.txt
#   test_v4_chacha20-poly1305_sha512_pbkdf2.txt  (uses default rounds)
# 
# - The prefix (v3, v4, v5) in the filename determines which metadata version and output directory to use
# - You can specify rounds for each hash and KDF using the format hash:rounds or kdf:rounds
# - If no rounds are specified, a default of 1 will be used

# Default settings
DEFAULT_PREFIX="v5"  # Default prefix if none specified in filename
TEST_PASSWORD="1234"
TEST_CONTENT="Hello World"
DRY_RUN=false

# Base directory for test files
BASE_OUTPUT_DIR="openssl_encrypt/unittests/testfiles"

# Available encryption algorithms
ALGORITHMS=("aes-gcm" "aes-gcm-siv" "aes-ocb3" "aes-siv" "chacha20-poly1305" "xchacha20-poly1305" "fernet")

# PQC Algorithms
PQC_ALGORITHMS=("ml-kem-512-hybrid" "ml-kem-768-hybrid" "ml-kem-1024-hybrid")

# Available encryption data options for PQC
ENC_DATA=("aes-gcm" "aes-gcm-siv" "aes-ocb3" "aes-siv" "chacha20-poly1305" "xchacha20-poly1305")

# Available hash algorithms
HASHES=("sha256" "sha512" "sha3-256" "sha3-512" "blake2b" "shake256" "whirlpool")

# Available KDFs
KDFS=("pbkdf2" "argon2" "balloon" "scrypt")

# Function to parse filename and extract parameters
parse_filename() {
    local filename="$1"
    # Remove file extension before splitting
    local basename="${filename%.txt}"
    local parts=(${basename//_/ })
    
    # Initialize variables with defaults
    local prefix="$DEFAULT_PREFIX"
    local algo="aes-gcm"
    local enc_data=""
    local extra_args=""
    local is_pqc=false
    
    # Check if second part is a prefix/version (v3, v4, v5, etc.)
    if [[ ${#parts[@]} -gt 1 && ${parts[1]} =~ ^v[0-9]+$ ]]; then
        prefix="${parts[1]}"
    fi
    
    # First pass: Look for PQC algorithm as primary algorithm
    for part in "${parts[@]}"; do
        # Check if this part specifies a PQC algorithm
        for pqc in "${PQC_ALGORITHMS[@]}"; do
            if [[ "$part" == "$pqc" ]]; then
                algo="$pqc"
                extra_args+=" --pqc-store-key --dual-encrypt-key"
                is_pqc=true
                break
            fi
        done
        # If we found a PQC algorithm, stop looking
        if [[ "$is_pqc" = true ]]; then
            break
        fi
    done
    
    # Extract parameters from filename parts
    for part in "${parts[@]}"; do
        # If we haven't found a PQC algorithm yet, check for standard algorithm
        if [[ "$is_pqc" = false ]]; then
            for a in "${ALGORITHMS[@]}"; do
                if [[ "$part" == "$a" ]]; then
                    algo="$part"
                    break
                fi
            done
        fi
        
        # Check if this part contains multiple hash algorithms (separated by +)
        if [[ "$part" == *"+"* ]]; then
            # Split the part by + to get individual hash algorithms
            IFS='+' read -ra hash_parts <<< "$part"
            
            for hash_spec in "${hash_parts[@]}"; do
                # Check if hash has rounds specified (hash:rounds format)
                if [[ "$hash_spec" == *":"* ]]; then
                    # Split hash and rounds
                    hash_name="${hash_spec%%:*}"
                    hash_rounds="${hash_spec#*:}"
                    
                    # Validate that rounds is a number
                    if ! [[ "$hash_rounds" =~ ^[0-9]+$ ]]; then
                        echo "Warning: Invalid rounds '$hash_rounds' for hash '$hash_name', using default of 1"
                        hash_rounds=1
                    fi
                else
                    # No rounds specified, use default
                    hash_name="$hash_spec"
                    hash_rounds=1
                fi
                
                # Check if this is a valid hash algorithm
                for h in "${HASHES[@]}"; do
                    if [[ "$hash_name" == "$h" ]]; then
                        # Add flag for hash with specified rounds
                        extra_args+=" --${hash_name}-rounds $hash_rounds"
                        break
                    fi
                done
            done
        else
            # Check if this part is a single hash algorithm
            for h in "${HASHES[@]}"; do
                # Check if hash has rounds specified (hash:rounds format)
                if [[ "$part" == "$h:"* ]]; then
                    # Split hash and rounds
                    hash_name="$h"
                    hash_rounds="${part#*:}"
                    
                    # Validate that rounds is a number
                    if ! [[ "$hash_rounds" =~ ^[0-9]+$ ]]; then
                        echo "Warning: Invalid rounds '$hash_rounds' for hash '$hash_name', using default of 1"
                        hash_rounds=1
                    fi
                    
                    # Add flag with specified rounds
                    extra_args+=" --${hash_name}-rounds $hash_rounds"
                    break
                elif [[ "$part" == "$h" ]]; then
                    # No rounds specified, use default
                    extra_args+=" --${h}-rounds 1"
                    break
                fi
            done
        fi
        
        # Check if this part contains multiple KDFs (separated by +)
        if [[ "$part" == *"+"* ]]; then
            # Split the part by + to get individual KDFs
            IFS='+' read -ra kdf_parts <<< "$part"
            
            for kdf_spec in "${kdf_parts[@]}"; do
                # Check if KDF has rounds specified (kdf:rounds format)
                if [[ "$kdf_spec" == *":"* ]]; then
                    # Split KDF and rounds
                    kdf_name="${kdf_spec%%:*}"
                    kdf_rounds="${kdf_spec#*:}"
                    
                    # Validate that rounds is a number
                    if ! [[ "$kdf_rounds" =~ ^[0-9]+$ ]]; then
                        echo "Warning: Invalid rounds '$kdf_rounds' for KDF '$kdf_name', using default of 1"
                        kdf_rounds=1
                    fi
                else
                    # No rounds specified, use default
                    kdf_name="$kdf_spec"
                    kdf_rounds=1
                fi
                
                # Check if this is a valid KDF
                for k in "${KDFS[@]}"; do
                    if [[ "$kdf_name" == "$k" ]]; then
                        case "$kdf_name" in
                            "argon2")
                                extra_args+=" --argon2-rounds $kdf_rounds"
                                ;;
                            "balloon")
                                extra_args+=" --balloon-rounds $kdf_rounds"
                                ;;
                            "scrypt")
                                # For scrypt, the rounds parameter is used for the 'n' parameter
                                extra_args+=" --scrypt-rounds $kdf_rounds"
                                ;;
                            "pbkdf2")
                                extra_args+=" --pbkdf2-iterations $kdf_rounds"
                                ;;
                        esac
                        break
                    fi
                done
            done
        else
            # Check if this part is a single KDF
            for k in "${KDFS[@]}"; do
                # Check if KDF has rounds specified (kdf:rounds format)
                if [[ "$part" == "$k:"* ]]; then
                    # Split KDF and rounds
                    kdf_name="$k"
                    kdf_rounds="${part#*:}"
                    
                    # Validate that rounds is a number
                    if ! [[ "$kdf_rounds" =~ ^[0-9]+$ ]]; then
                        echo "Warning: Invalid rounds '$kdf_rounds' for KDF '$kdf_name', using default of 1"
                        kdf_rounds=1
                    fi
                    
                    # Add appropriate flags with specified rounds
                    case "$kdf_name" in
                        "argon2")
                            extra_args+=" --argon2-rounds $kdf_rounds"
                            ;;
                        "balloon")
                            extra_args+=" --balloon-rounds $kdf_rounds"
                            ;;
                        "scrypt")
                            extra_args+=" --scrypt-rounds $kdf_rounds"
                            ;;
                        "pbkdf2")
                            extra_args+=" --pbkdf2-iterations $kdf_rounds"
                            ;;
                    esac
                    break
                elif [[ "$part" == "$k" ]]; then
                    # No rounds specified, use default of 1
                    case "$k" in
                        "argon2")
                            extra_args+=" --argon2-rounds 1"
                            ;;
                        "balloon")
                            extra_args+=" --balloon-rounds 1"
                            ;;
                        "scrypt")
                            extra_args+=" --scrypt-rounds 1"
                            ;;
                        "pbkdf2")
                            extra_args+=" --pbkdf2-iterations 1"
                            ;;
                    esac
                    break
                fi
            done
        fi
        
        # Check if this part specifies encryption data for PQC
        for e in "${ENC_DATA[@]}"; do
            if [[ "$part" == "$e" ]]; then
                enc_data="$e"
                break
            fi
        done
    done
    
    # If it's a PQC algorithm and no encryption data is specified, pick a random one
    if [[ "$algo" =~ (ml-kem|hqc) && -z "$enc_data" ]]; then
        enc_data="${ENC_DATA[RANDOM % ${#ENC_DATA[@]}]}"
    fi
    
    # Add encryption data if specified and it's a PQC algorithm
    if [[ -n "$enc_data" && "$is_pqc" = true ]]; then
        extra_args+=" --encryption-data $enc_data"
    fi
    
    # Add default KDF if none specified
    if [[ ! "$extra_args" =~ (argon2-rounds|balloon-rounds|scrypt-rounds|pbkdf2-iterations) ]]; then
        extra_args+=" --pbkdf2-iterations 10000"
    fi
    
    echo "$prefix" "$algo" "$extra_args"
}

# Function to generate a test file with given parameters
generate_test_file() {
    local filename="$1"
    local prefix="$2"
    local algo="$3"
    local extra_args="$4"
    
    # Set output directory based on prefix
    local output_dir="${BASE_OUTPUT_DIR}/${prefix}"
    
    # Command to execute
    local cmd="python -m openssl_encrypt.crypt encrypt -i /tmp/test_input.txt -o \"${output_dir}/${filename}\" \
        --algorithm \"${algo}\" --password \"${TEST_PASSWORD}\" --force-password ${extra_args}"
    
    echo "Generating test file: ${filename}"
    echo "  Metadata version: ${prefix}"
    echo "  Algorithm: ${algo}"
    echo "  Extra args: ${extra_args}"
    
    if [[ "$DRY_RUN" = true ]]; then
        echo "  DRY RUN - Command that would be executed:"
        echo "  mkdir -p \"${output_dir}\""
        echo "  $cmd"
        echo "  [Not actually running the command]"
    else
        # Ensure output directory exists
        mkdir -p "${output_dir}"
        
        # Execute the encryption command
        eval "$cmd"
        
        # Verify that the file was created successfully
        if [[ -f "${output_dir}/${filename}" ]]; then
            echo "  Created successfully!"
        else
            echo "  ERROR: Failed to create test file!"
        fi
    fi
    echo
}

# Show usage information
show_usage() {
    echo "Usage: $0 [options] [test_filename.txt ...]"
    echo ""
    echo "Options:"
    echo "  --dryrun          Print commands without executing them"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                             # Generate default test files"
    echo "  $0 --dryrun                    # Show commands without executing them"
    echo "  $0 test_v4_aes-gcm_sha512_pbkdf2.txt # Generate file with v4 metadata"
    echo "  $0 test_v3_ml-kem-768-hybrid_sha512+sha256_argon2+pbkdf2_aes-gcm.txt"
    echo ""
    echo "Filename format: test_[prefix]_[algo]_[hash1+hash2+...]_[kdf1+kdf2+...]_[encryption_data].txt"
    echo "  - [prefix]: v3, v4, v5, etc. - determines metadata version and output directory"
    echo "  - Specify rounds for hashes and KDFs using hash:rounds or kdf:rounds syntax"
    echo "  - If no rounds specified, defaults to 1"
}

# Process command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_usage
            exit 0
            ;;
        --dryrun)
            DRY_RUN=true
            shift
            ;;
        -b|--base)
           shift
           BASE_OUTPUT_DIR="$1"
           shift
           ;;
        *)
            break
            ;;
    esac
done

# Create a test file with content if not in dry run mode
if [[ "$DRY_RUN" = true ]]; then
    echo "DRY RUN MODE - Commands will be printed but not executed"
    echo "Would create /tmp/test_input.txt with content: ${TEST_CONTENT}"
    echo
else
    echo "${TEST_CONTENT}" > /tmp/test_input.txt
fi

# Generate test files based on command line arguments or default patterns
if [[ $# -gt 0 ]]; then
    # Generate files based on command line arguments
    for filename in "$@"; do
        read prefix algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
    done
else
    # Generate a standard set of test files with various combinations
    
    # Generate tests for each metadata version
    for metadata_version in "v3" "v4" "v5"; do
        echo "Generating default test files for metadata version ${metadata_version}..."
        
        # Basic tests with different algorithms
        for algo in "aes-gcm" "aes-gcm-siv" "chacha20-poly1305" "xchacha20-poly1305" "fernet"; do
            filename="test_${metadata_version}_${algo}_sha512:1000_pbkdf2:10000.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
        done
        
        # Tests with different KDFs and different rounds
        for kdf in "pbkdf2" "argon2" "balloon" "scrypt"; do
            case "$kdf" in
                "pbkdf2")
                    rounds="100000"
                    ;;
                "argon2")
                    rounds="10"
                    ;;
                "balloon")
                    rounds="3"
                    ;;
                "scrypt")
                    rounds="1024"
                    ;;
            esac
            filename="test_${metadata_version}_aes-gcm_sha512:1000_${kdf}:${rounds}.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
        done
        
        # Tests with multiple KDFs (only for v5 for simplicity)
        if [[ "$metadata_version" == "v5" ]]; then
            # Tests with multiple KDFs with specified rounds
            filename="test_${metadata_version}_aes-gcm_sha512:1000_pbkdf2:100000+argon2:10.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            
            filename="test_${metadata_version}_aes-gcm_sha512:1000_argon2:15+balloon:4.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            
            # Tests with different hashes and rounds
            for hash in "sha256" "sha512" "sha3-256" "sha3-512" "blake2b"; do
                rounds=$((RANDOM % 10000 + 1000))  # Random rounds between 1000-11000
                filename="test_${metadata_version}_aes-gcm_${hash}:${rounds}_pbkdf2:50000.txt"
                read prefix algo extra_args < <(parse_filename "$filename")
                generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            done
            
            # Tests with multiple hashes and specified rounds
            filename="test_${metadata_version}_aes-gcm_sha256:5000+sha512:10000_pbkdf2:100000.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            
            filename="test_${metadata_version}_aes-gcm_sha512:8000+blake2b:6000+whirlpool:4000_pbkdf2:100000.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            
            # Test with multiple hashes and multiple KDFs with specified rounds
            filename="test_${metadata_version}_aes-gcm_sha256:5000+sha512:10000_pbkdf2:100000+argon2:10.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            
            # Tests with default rounds (should use 1)
            filename="test_${metadata_version}_aes-gcm_sha512_pbkdf2.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            
            # Tests with PQC algorithms and multiple hashes/KDFs with rounds
            for pqc in "ml-kem-512-hybrid" "ml-kem-768-hybrid"; do
                filename="test_${metadata_version}_${pqc}_sha512:10000+sha256:5000_argon2:10+pbkdf2:100000_aes-gcm.txt"
                read prefix algo extra_args < <(parse_filename "$filename")
                generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            done
            
            # Tests with HQC algorithms and multiple hashes/KDFs with rounds
            for pqc in "hqc-128-hybrid"; do
                filename="test_${metadata_version}_${pqc}_sha512:10000+blake2b:8000_argon2:15+balloon:3_chacha20-poly1305.txt"
                read prefix algo extra_args < <(parse_filename "$filename")
                generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            done
        fi
    done
fi

# Clean up temp file if not in dry run mode
if [[ "$DRY_RUN" = true ]]; then
    echo "Would remove temporary file: /tmp/test_input.txt"
else
    rm -f /tmp/test_input.txt
fi

echo "Test file generation complete!"
