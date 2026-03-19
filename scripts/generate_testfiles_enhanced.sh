#!/usr/bin/env bash

# Enhanced script to generate test files with parameters derived from filenames
# Filename format: test_[prefix]_[algo]_[hash1=rounds+hash2=rounds+...]_[kdf1=rounds+kdf2=rounds+...]_[encryption_data].txt
# Examples:
#   test_v12_aes-gcm_sha512=2+sha256=2_argon2=2+scrypt=2.txt
#   test_v12_chacha20-poly1305_sha512_argon2.txt  (uses default rounds)
#
# - The prefix (v12, etc.) in the filename determines which metadata version and output directory to use
# - You can specify rounds for each hash and KDF using the format hash=rounds or kdf=rounds
# - If no rounds are specified, a default of 2 will be used (balloon defaults to 1)

# Default settings
DEFAULT_PREFIX="v12"  # Default prefix if none specified in filename
TEST_PASSWORD="1234"
TEST_CONTENT="Hello World"
DRY_RUN=false

# Python executable - use venv if available
if [[ -x ".venv/bin/python" ]]; then
    PYTHON=".venv/bin/python"
else
    PYTHON="python"
fi

# Base directory for test files
BASE_OUTPUT_DIR="openssl_encrypt/unittests/testfiles"

# Available encryption algorithms
ALGORITHMS=("aes-gcm" "aes-gcm-siv" "aes-siv" "chacha20-poly1305" "xchacha20-poly1305" "fernet" "threefish-512" "threefish-1024")

# PQC Algorithms
PQC_ALGORITHMS=(
    "ml-kem-512-hybrid" "ml-kem-768-hybrid" "ml-kem-1024-hybrid"
    "ml-kem-512-chacha20" "ml-kem-768-chacha20" "ml-kem-1024-chacha20"
    "hqc-128-hybrid" "hqc-192-hybrid" "hqc-256-hybrid"
    "mayo-1-hybrid" "mayo-3-hybrid" "mayo-5-hybrid"
    "cross-128-hybrid" "cross-192-hybrid" "cross-256-hybrid"
)

# Available encryption data options for PQC
ENC_DATA=("aes-gcm" "aes-gcm-siv" "aes-siv" "chacha20-poly1305" "xchacha20-poly1305" "threefish-512" "threefish-1024")

# Available hash algorithms
HASHES=("sha256" "sha384" "sha512" "sha3-256" "sha3-384" "sha3-512" "blake2b" "blake3" "shake128" "shake256")

# Available KDFs
KDFS=("argon2" "balloon" "scrypt" "randomx")

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
    local is_cascade=false

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
                extra_args+=" --pqc-store-key"
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
        # Check for cascade mode (before standard algorithm check)
        if [[ "$part" == "cascade-standard" ]]; then
            algo="cascade"
            extra_args+=" --cascade=standard"
            is_cascade=true
        elif [[ "$part" == "cascade-paranoia" ]]; then
            algo="cascade"
            extra_args+=" --cascade=paranoia"
            is_cascade=true
        elif [[ "$part" == cascade~* ]]; then
            # Custom cascade chain: cascade~algo1~algo2[~algo3]
            local chain="${part#cascade~}"
            algo="${chain//\~/,}"
            extra_args+=" --cascade"
            is_cascade=true
        fi

        # If we haven't found a PQC or cascade algorithm, check for standard algorithm
        if [[ "$is_pqc" = false && "$is_cascade" = false ]]; then
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
                # Check if hash has rounds specified (hash=rounds format)
                if [[ "$hash_spec" == *"="* ]]; then
                    # Split hash and rounds
                    hash_name="${hash_spec%%=*}"
                    hash_rounds="${hash_spec#*=}"

                    # Validate that rounds is a number
                    if ! [[ "$hash_rounds" =~ ^[0-9]+$ ]]; then
                        echo "Warning: Invalid rounds '$hash_rounds' for hash '$hash_name', using default of 2"
                        hash_rounds=2
                    fi
                else
                    # No rounds specified, use default
                    hash_name="$hash_spec"
                    hash_rounds=2
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
                # Check if hash has rounds specified (hash=rounds format)
                if [[ "$part" == "$h="* ]]; then
                    # Split hash and rounds
                    hash_name="$h"
                    hash_rounds="${part#*=}"

                    # Validate that rounds is a number
                    if ! [[ "$hash_rounds" =~ ^[0-9]+$ ]]; then
                        echo "Warning: Invalid rounds '$hash_rounds' for hash '$hash_name', using default of 2"
                        hash_rounds=2
                    fi

                    # Add flag with specified rounds
                    extra_args+=" --${hash_name}-rounds $hash_rounds"
                    break
                elif [[ "$part" == "$h" ]]; then
                    # No rounds specified, use default
                    extra_args+=" --${h}-rounds 2"
                    break
                fi
            done
        fi

        # Check if this part contains multiple KDFs (separated by +)
        if [[ "$part" == *"+"* ]]; then
            # Split the part by + to get individual KDFs
            IFS='+' read -ra kdf_parts <<< "$part"

            for kdf_spec in "${kdf_parts[@]}"; do
                # Check if KDF has rounds specified (kdf=rounds format)
                if [[ "$kdf_spec" == *"="* ]]; then
                    # Split KDF and rounds
                    kdf_name="${kdf_spec%%=*}"
                    kdf_rounds="${kdf_spec#*=}"

                    # Validate that rounds is a number
                    if ! [[ "$kdf_rounds" =~ ^[0-9]+$ ]]; then
                        echo "Warning: Invalid rounds '$kdf_rounds' for KDF '$kdf_name', using default of 2"
                        kdf_rounds=2
                    fi
                else
                    # No rounds specified, use default (2 for all, 1 for balloon)
                    kdf_name="$kdf_spec"
                    if [[ "$kdf_name" == "balloon" ]]; then
                        kdf_rounds=1
                    else
                        kdf_rounds=2
                    fi
                fi

                # Check if this is a valid KDF
                for k in "${KDFS[@]}"; do
                    if [[ "$kdf_name" == "$k" ]]; then
                        case "$kdf_name" in
                            "argon2")
                                extra_args+=" --argon2-rounds $kdf_rounds"
                                ;;
                            "balloon")
                                # Cap balloon rounds at 1 to avoid slow tests
                                [[ $kdf_rounds -gt 1 ]] && kdf_rounds=1
                                extra_args+=" --balloon-rounds $kdf_rounds"
                                ;;
                            "scrypt")
                                # For scrypt, the rounds parameter is used for the 'n' parameter
                                extra_args+=" --scrypt-rounds $kdf_rounds"
                                ;;
                            "randomx")
                                extra_args+=" --enable-randomx --randomx-rounds $kdf_rounds"
                                ;;
                            esac
                        break
                    fi
                done
            done
        else
            # Check if this part is a single KDF
            for k in "${KDFS[@]}"; do
                # Check if KDF has rounds specified (kdf=rounds format)
                if [[ "$part" == "$k="* ]]; then
                    # Split KDF and rounds
                    kdf_name="$k"
                    kdf_rounds="${part#*=}"

                    # Validate that rounds is a number
                    if ! [[ "$kdf_rounds" =~ ^[0-9]+$ ]]; then
                        echo "Warning: Invalid rounds '$kdf_rounds' for KDF '$kdf_name', using default of 2"
                        kdf_rounds=2
                    fi

                    # Add appropriate flags with specified rounds
                    case "$kdf_name" in
                        "argon2")
                            extra_args+=" --argon2-rounds $kdf_rounds"
                            ;;
                        "balloon")
                            # Cap balloon rounds at 1 to avoid slow tests
                            [[ $kdf_rounds -gt 1 ]] && kdf_rounds=1
                            extra_args+=" --balloon-rounds $kdf_rounds"
                            ;;
                        "scrypt")
                            extra_args+=" --scrypt-rounds $kdf_rounds"
                            ;;
                        "randomx")
                            extra_args+=" --enable-randomx --randomx-rounds $kdf_rounds"
                            ;;
                    esac
                    break
                elif [[ "$part" == "$k" ]]; then
                    # No rounds specified, use default (2 for all, 1 for balloon)
                    case "$k" in
                        "argon2")
                            extra_args+=" --argon2-rounds 2"
                            ;;
                        "balloon")
                            extra_args+=" --balloon-rounds 1"
                            ;;
                        "scrypt")
                            extra_args+=" --scrypt-rounds 2"
                            ;;
                        "randomx")
                            extra_args+=" --enable-randomx --randomx-rounds 2"
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
    if [[ "$algo" =~ (ml-kem|hqc|mayo|cross) && -z "$enc_data" ]]; then
        enc_data="${ENC_DATA[RANDOM % ${#ENC_DATA[@]}]}"
    fi

    # Add encryption data if specified and it's a PQC algorithm
    if [[ -n "$enc_data" && "$is_pqc" = true ]]; then
        extra_args+=" --encryption-data $enc_data"
    fi

    # Add default KDF if none specified
    if [[ ! "$extra_args" =~ (argon2-rounds|balloon-rounds|scrypt-rounds|randomx-rounds) ]]; then
        extra_args+=" --argon2-rounds 2"
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
    local cmd="${PYTHON} -m openssl_encrypt.crypt encrypt -i /tmp/test_input.txt -o \"${output_dir}/${filename}\" \
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
    echo "  $0 test_v4_aes-gcm_sha512_argon2.txt # Generate file with v4 metadata"
    echo "  $0 test_v3_ml-kem-768-hybrid_sha512+sha256_argon2+scrypt_aes-gcm.txt"
    echo "  $0 test_v5_threefish-512_blake3=1000_randomx=2.txt"
    echo "  $0 test_v5_cascade-standard_sha512=1000_argon2=2.txt"
    echo "  $0 test_v5_cascade~aes-gcm~chacha20-poly1305~threefish-512_sha512=1000_argon2=2.txt"
    echo ""
    echo "Filename format: test_[prefix]_[algo]_[hash1+hash2+...]_[kdf1+kdf2+...]_[encryption_data].txt"
    echo "  - [prefix]: v3, v4, v5, etc. - determines metadata version and output directory"
    echo "  - Supported KDFs: argon2, balloon, scrypt, randomx"
    echo "  - Cascade: use 'cascade-standard', 'cascade-paranoia' (presets)"
    echo "    or 'cascade~algo1~algo2[~algo3]' (custom chain, max 3 algos)"
    echo "  - Specify rounds for hashes and KDFs using hash=rounds or kdf=rounds syntax"
    echo "  - If no rounds specified, defaults to 2 (balloon defaults to 1)"
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
    # Generate a comprehensive set of test files
    # Target: ~840 files covering full singles matrix, representative chains,
    # cascade full matrix, and PQC algorithms

    metadata_version="v12"
    echo "Generating test files for metadata version ${metadata_version}..."

    # Helper to get KDF rounds (balloon max 1, others 2)
    kdf_rounds() {
        case "$1" in
            "balloon") echo "1" ;;
            *) echo "2" ;;
        esac
    }

    # ================================================================
    # SECTION 1: Full singles matrix (320 files)
    # 10 hashes × 4 KDFs × 8 enc algos
    # ================================================================
    echo "--- Section 1: Full singles matrix (10 hashes × 4 KDFs × 8 enc algos = 320) ---"
    for enc in "${ALGORITHMS[@]}"; do
        for hash in "${HASHES[@]}"; do
            for kdf in "${KDFS[@]}"; do
                kr=$(kdf_rounds "$kdf")
                filename="test_${metadata_version}_${enc}_${hash}=2_${kdf}=${kr}.txt"
                read prefix algo extra_args < <(parse_filename "$filename")
                generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            done
        done
    done

    # ================================================================
    # SECTION 2: Representative hash/KDF chains × all enc algos (200 files)
    # 25 chain combos × 8 enc algos
    # ================================================================
    echo "--- Section 2: Representative hash/KDF chains × 8 enc algos = 200 ---"

    # Multi-hash chains (9 combos)
    MULTI_HASHES=(
        # 2-hash chains (5)
        "sha256=2+sha512=2"
        "sha3-256=2+blake2b=2"
        "blake3=2+shake256=2"
        "sha384=2+sha3-384=2"
        "shake128=2+sha3-512=2"
        # 3-hash chains (3)
        "sha512=2+blake2b=2+sha3-256=2"
        "sha256=2+sha384=2+blake3=2"
        "shake128=2+sha3-512=2+sha3-384=2"
        # All 10 hashes chained (1)
        "sha256=2+sha384=2+sha512=2+sha3-256=2+sha3-384=2+sha3-512=2+blake2b=2+blake3=2+shake128=2+shake256=2"
    )

    # Multi-KDF chains (11 combos)
    MULTI_KDFS=(
        # 2-KDF chains - all C(4,2)=6
        "argon2=2+scrypt=2"
        "argon2=2+balloon=1"
        "argon2=2+randomx=2"
        "scrypt=2+balloon=1"
        "scrypt=2+randomx=2"
        "balloon=1+randomx=2"
        # 3-KDF chains - all C(4,3)=4
        "argon2=2+scrypt=2+balloon=1"
        "argon2=2+scrypt=2+randomx=2"
        "argon2=2+balloon=1+randomx=2"
        "scrypt=2+balloon=1+randomx=2"
        # All 4 KDFs chained (1)
        "argon2=2+scrypt=2+balloon=1+randomx=2"
    )

    # Cross combos: multi-hash + multi-KDF (5 combos)
    CROSS_HASH=(
        "sha256=2+sha512=2"
        "sha3-256=2+blake2b=2"
        "blake3=2+shake256=2"
        "sha512=2+blake2b=2+sha3-256=2"
        "sha256=2+sha384=2+sha512=2+sha3-256=2+sha3-384=2+sha3-512=2+blake2b=2+blake3=2+shake128=2+shake256=2"
    )
    CROSS_KDF=(
        "argon2=2+scrypt=2"
        "argon2=2+balloon=1"
        "scrypt=2+randomx=2"
        "argon2=2+scrypt=2+balloon=1"
        "argon2=2+scrypt=2+balloon=1+randomx=2"
    )

    for enc in "${ALGORITHMS[@]}"; do
        # Multi-hash with single default KDF (argon2)
        for mh in "${MULTI_HASHES[@]}"; do
            filename="test_${metadata_version}_${enc}_${mh}_argon2=2.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
        done

        # Multi-KDF with single default hash (sha512)
        for mk in "${MULTI_KDFS[@]}"; do
            filename="test_${metadata_version}_${enc}_sha512=2_${mk}.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
        done

        # Cross: multi-hash + multi-KDF
        for i in "${!CROSS_HASH[@]}"; do
            filename="test_${metadata_version}_${enc}_${CROSS_HASH[$i]}_${CROSS_KDF[$i]}.txt"
            read prefix algo extra_args < <(parse_filename "$filename")
            generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
        done
    done

    # ================================================================
    # SECTION 3: Cascade full hash×KDF matrix (320 files)
    # 8 cascade variants × 10 hashes × 4 KDFs
    # ================================================================
    echo "--- Section 3: Cascade full matrix (8 cascades × 10 hashes × 4 KDFs = 320) ---"

    CASCADE_VARIANTS=(
        # Presets (2)
        "cascade-standard"
        "cascade-paranoia"
        # Custom 2-algo chains (3)
        "cascade~aes-gcm~xchacha20-poly1305"
        "cascade~chacha20-poly1305~threefish-512"
        "cascade~aes-gcm-siv~threefish-1024"
        # Custom 3-algo chains (3)
        "cascade~aes-gcm~chacha20-poly1305~threefish-512"
        "cascade~xchacha20-poly1305~aes-gcm-siv~threefish-1024"
        "cascade~aes-gcm~aes-siv~xchacha20-poly1305"
    )

    for cascade in "${CASCADE_VARIANTS[@]}"; do
        for hash in "${HASHES[@]}"; do
            for kdf in "${KDFS[@]}"; do
                kr=$(kdf_rounds "$kdf")
                filename="test_${metadata_version}_${cascade}_${hash}=2_${kdf}=${kr}.txt"
                read prefix algo extra_args < <(parse_filename "$filename")
                generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
            done
        done
    done

    # ================================================================
    # SECTION 4: PQC algorithms (representative tests)
    # ================================================================
    echo "--- Section 4: PQC algorithms ---"

    # ML-KEM hybrid variants
    for pqc in "ml-kem-512-hybrid" "ml-kem-768-hybrid"; do
        filename="test_${metadata_version}_${pqc}_sha512=2+sha256=2_argon2=2_aes-gcm.txt"
        read prefix algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
    done

    # ML-KEM-ChaCha20 variants
    filename="test_${metadata_version}_ml-kem-768-chacha20_sha512=2_argon2=2_chacha20-poly1305.txt"
    read prefix algo extra_args < <(parse_filename "$filename")
    generate_test_file "$filename" "$prefix" "$algo" "$extra_args"

    # HQC variants
    for pqc in "hqc-128-hybrid" "hqc-192-hybrid"; do
        filename="test_${metadata_version}_${pqc}_sha512=2+blake2b=2_argon2=2+balloon=1_chacha20-poly1305.txt"
        read prefix algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
    done

    # MAYO variants
    for pqc in "mayo-1-hybrid" "mayo-3-hybrid"; do
        filename="test_${metadata_version}_${pqc}_sha3-256=2_argon2=2_aes-gcm.txt"
        read prefix algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
    done

    # CROSS variants
    for pqc in "cross-128-hybrid" "cross-192-hybrid"; do
        filename="test_${metadata_version}_${pqc}_blake3=2_argon2=2_aes-gcm-siv.txt"
        read prefix algo extra_args < <(parse_filename "$filename")
        generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
    done

    # PQC with Threefish as encryption data
    filename="test_${metadata_version}_ml-kem-1024-hybrid_sha512=2_argon2=2_threefish-512.txt"
    read prefix algo extra_args < <(parse_filename "$filename")
    generate_test_file "$filename" "$prefix" "$algo" "$extra_args"
fi

# Clean up temp file if not in dry run mode
if [[ "$DRY_RUN" = true ]]; then
    echo "Would remove temporary file: /tmp/test_input.txt"
else
    rm -f /tmp/test_input.txt
fi

echo "Test file generation complete!"
