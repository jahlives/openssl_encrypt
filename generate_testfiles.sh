#!/usr/bin/env bash

# Create v5 test files with proper dual encryption handling
OUTPUT='openssl_encrypt/unittests/testfiles/v5'
my_array=("aes-gcm" "aes-gcm-siv" "aes-ocb3" "aes-siv" "chacha20-poly1305" "xchacha20-poly1305")

# Ensure output directory exists
mkdir -p ${OUTPUT}

# Create a test file with content
echo "Hello World" > /tmp/test_input.txt

for FILE in test1_aes-gcm-siv.txt  test1_aes-ocb3.txt  test1_chacha20-poly1305.txt  test1_fernet.txt     test1_kyber512.txt  test1_xchacha20-poly1305.txt test1_aes-gcm.txt      test1_aes-siv.txt   test1_fernet_balloon.txt     test1_kyber1024.txt  test1_kyber768.txt ; do
  ALGO=${FILE}
  ALGO=${ALGO#test1_}
  ALGO=${ALGO%.txt}
  END=''
  ALGO_Q=""
  
  if [[ $ALGO =~ 'kyber' ]] ; then 
    # Properly implement dual encryption by using pqc-store-key AND dual-encrypt-key
    # with a known password so that tests can verify password validation
    END='--pqc-store-key --dual-encrypt-key'
    ALGO="${ALGO}-hybrid"
    # Randomly select data encryption algorithm for v5 metadata format
    ALGO_Q="--encryption-data ${my_array[RANDOM % ${#my_array[@]}]}"
  elif [[ $ALGO =~ '_balloon' ]] ; then
    ALGO=${ALGO%_balloon}
    END='--enable-balloon --balloon-rounds 1'
  fi
  
  # Generate test files using consistent password 1234
  python -m openssl_encrypt.crypt encrypt -i /tmp/test_input.txt -o ${OUTPUT}/${FILE} \
    --algorithm ${ALGO} --password 1234 --force-password \
    --pbkdf2-iteration 10000 --enable-argon2 --argon2-rounds 10 ${ALGO_Q} ${END}
    
  # Verify that the file was created successfully
  if [[ -f ${OUTPUT}/${FILE} ]]; then
    echo "Created test file: ${OUTPUT}/${FILE}"
  else
    echo "ERROR: Failed to create test file: ${OUTPUT}/${FILE}"
  fi
done

# Clean up temp file
rm -f /tmp/test_input.txt

echo "Test file generation complete!"
