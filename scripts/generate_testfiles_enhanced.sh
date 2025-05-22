#!/usr/bin/env bash

# Enhanced script to generate test files with parameters derived from filenames
# Filename format: test_[algo]_[hash1+hash2+...]_[kdf1+kdf2+...]_[encryption_data].txt
# Example: test_aes-gcm_sha512+sha256_argon2+pbkdf2_standard.txt
# 
# Note: Different metadata versions are handled by output directories (v3, v4, v5),
# not in the filename itself.

# Output directory - default to v5 but can be changed
OUTPUT='openssl_encrypt/unittests/testfiles/v5'
TEST_PASSWORD="1234"
TEST_CONTENT="Hello World"

# Available encryption algorithms
ALGORITHMS=("aes-gcm" "aes-gcm-siv" "aes-ocb3" "aes-siv" "chacha20-poly1305" "xchacha20-poly1305" 
            "fernet" "ml-kem-512-hybrid" "ml-kem-768-hybrid" "ml-kem-1024-hybrid" 
            "hqc-128-hybrid" "hqc-192-hybrid" "hqc-256-hybrid")

# Available encryption data options for PQC
ENC_DATA=("aes-gcm" "aes-gcm-siv" "aes-ocb3" "aes-siv" "chacha20-poly1305" "xchacha20-poly1305")

# Available hash algorithms
HASHES=("sha256" "sha512" "sha3-256" "sha3-512" "blake2b" "shake256" "whirlpool")

# Available KDFs
KDFS=("pbkdf2" "argon2" "balloon" "scrypt")

# Ensure output directory exists
mkdir -p ${OUTPUT}

# Create a test file with content
echo "${TEST_CONTENT}" > /tmp/test_input.txt

# Function to parse filename and extract parameters
parse_filename() {
    local filename="$1"
    local parts=(${filename//_/ })
    
    # Initialize variables with defaults
    local algo="aes-gcm"
    local enc_data=""
    local extra_args=""
    
    # Extract parameters from filename parts
    for part in "${parts[@]}"; do
        # Check if this part specifies an algorithm
        for a in "${ALGORITHMS[@]}"; do
            if [[ "$part" == "$a" || "$part" == "${a}-hybrid" ]]; then
                algo="$part"
                # If it's a PQC algorithm, add the required flags
                if [[ "$part" =~ (kyber|ml-kem|hqc) ]]; then
                    extra_args+=" --pqc-store-key --dual-encrypt-key"
                fi
                break
            fi
        done
        
        # Check if this part contains multiple hash algorithms (separated by +)
        if [[ "$part" == *"+"* ]]; then
            # Split the part by + to get individual hash algorithms
            IFS='+' read -ra hash_parts <<< "$part"
            
            for hash in "${hash_parts[@]}"; do
                for h in "${HASHES[@]}"; do
                    if [[ "$hash" == "$h" ]]; then
                        # Add flag for each hash with default rounds
                        extra_args+=" --${hash//-/_}_rounds 10000"
                        break
                    fi
                done
            done
        else
            # Check if this part is a single hash algorithm
            for h in "${HASHES[@]}"; do
                if [[ "$part" == "$h" ]]; then
                    extra_args+=" --${part//-/_}_rounds 10000"
                    break
                fi
            done
        fi
        
        # Check if this part contains multiple KDFs (separated by +)
        if [[ "$part" == *"+"* ]]; then
            # Split the part by + to get individual KDFs
            IFS='+' read -ra kdf_parts <<< "$part"
            
            for kdf in "${kdf_parts[@]}"; do
                for k in "${KDFS[@]}"; do
                    if [[ "$kdf" == "$k" ]]; then
                        case "$kdf" in
                            "argon2")
                                extra_args+=" --enable-argon2 --argon2-rounds 10"
                                ;;
                            "balloon")
                                extra_args+=" --enable-balloon --balloon-rounds 1"
                                ;;
                            "scrypt")
                                extra_args+=" --enable-scrypt --scrypt-n 1024"
                                ;;
                            "pbkdf2")
                                extra_args+=" --pbkdf2-iterations 10000"
                                ;;
                        esac
                        break
                    fi
                done
            done
        else
            # Check if this part is a single KDF
            for k in "${KDFS[@]}"; do
                if [[ "$part" == "$k" ]]; then
                    case "$part" in
                        "argon2")
                            extra_args+=" --enable-argon2 --argon2-rounds 10"
                            ;;
                        "balloon")
                            extra_args+=" --enable-balloon --balloon-rounds 1"
                            ;;
                        "scrypt")
                            extra_args+=" --enable-scrypt --scrypt-n 1024"
                            ;;
                        "pbkdf2")
                            extra_args+=" --pbkdf2-iterations 10000"
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
    if [[ "$algo" =~ (kyber|ml-kem|hqc) && -z "$enc_data" ]]; then
        enc_data="${ENC_DATA[RANDOM % ${#ENC_DATA[@]}]}"
    fi
    
    # Add encryption data if specified
    if [[ -n "$enc_data" ]]; then
        extra_args+=" --encryption-data $enc_data"
    fi
    
    # Add default KDF if none specified
    if [[ ! "$extra_args" =~ (enable-argon2|enable-balloon|enable-scrypt|pbkdf2-iterations) ]]; then
        extra_args+=" --pbkdf2-iterations 10000"
    fi
    
    echo "$algo" "$extra_args"
}

# Function to generate a test file with given parameters
generate_test_file() {
    local filename="$1"
    local algo="$2"
    local extra_args="$3"
    
    echo "Generating test file: ${filename}"
    echo "  Algorithm: ${algo}"
    echo "  Extra args: ${extra_args}"
    
    # Execute the encryption command
    python -m openssl_encrypt.crypt encrypt -i /tmp/test_input.txt -o "${OUTPUT}/${filename}" \
        --algorithm "${algo}" --password "${TEST_PASSWORD}" --force-password ${extra_args}
        
    # Verify that the file was created successfully
    if [[ -f "${OUTPUT}/${filename}" ]]; then
        echo "  Created successfully!"
    else
        echo "  ERROR: Failed to create test file!"
    fi
    echo
}

# Generate test files based on command line arguments or default patterns
if [[ $# -gt 0 ]]; then
    # Generate files based on command line arguments
    for filename in "$@"; do
        read algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$algo" "$extra_args"
    done
else
    # Generate a standard set of test files with various combinations
    
    # Basic tests with different algorithms
    for algo in "aes-gcm" "aes-gcm-siv" "chacha20-poly1305" "xchacha20-poly1305" "fernet"; do
        filename="test_${algo}_sha512_pbkdf2.txt"
        read algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$algo" "$extra_args"
    done
    
    # Tests with different KDFs
    for kdf in "pbkdf2" "argon2" "balloon" "scrypt"; do
        filename="test_aes-gcm_sha512_${kdf}.txt"
        read algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$algo" "$extra_args"
    done
    
    # Tests with multiple KDFs
    filename="test_aes-gcm_sha512_pbkdf2+argon2.txt"
    read algo extra_args < <(parse_filename "$filename")
    generate_test_file "$filename" "$algo" "$extra_args"
    
    filename="test_aes-gcm_sha512_argon2+balloon.txt"
    read algo extra_args < <(parse_filename "$filename")
    generate_test_file "$filename" "$algo" "$extra_args"
    
    # Tests with different hashes
    for hash in "sha256" "sha512" "sha3-256" "sha3-512" "blake2b"; do
        filename="test_aes-gcm_${hash}_pbkdf2.txt"
        read algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$algo" "$extra_args"
    done
    
    # Tests with multiple hashes
    filename="test_aes-gcm_sha256+sha512_pbkdf2.txt"
    read algo extra_args < <(parse_filename "$filename")
    generate_test_file "$filename" "$algo" "$extra_args"
    
    filename="test_aes-gcm_sha512+blake2b+whirlpool_pbkdf2.txt"
    read algo extra_args < <(parse_filename "$filename")
    generate_test_file "$filename" "$algo" "$extra_args"
    
    # Test with multiple hashes and multiple KDFs
    filename="test_aes-gcm_sha256+sha512_pbkdf2+argon2.txt"
    read algo extra_args < <(parse_filename "$filename")
    generate_test_file "$filename" "$algo" "$extra_args"
    
    # Tests with PQC algorithms and multiple hashes/KDFs
    for pqc in "ml-kem-512-hybrid" "ml-kem-768-hybrid"; do
        filename="test_${pqc}_sha512+sha256_argon2+pbkdf2_aes-gcm.txt"
        read algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$algo" "$extra_args"
    done
    
    # Tests with HQC algorithms and multiple hashes/KDFs if available
    for pqc in "hqc-128-hybrid"; do
        filename="test_${pqc}_sha512+blake2b_argon2+balloon_chacha20-poly1305.txt"
        read algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$algo" "$extra_args"
    done
fi

# Clean up temp file
rm -f /tmp/test_input.txt

echo "Test file generation complete!"