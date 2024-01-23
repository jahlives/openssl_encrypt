# openssl-crypt

Bash Wrapper for encrypting and decrypting files via `openssl`. It uses a `python` script in the background and requires `python 2.x` so on modern systems a `venv` is needed.

## All
```
# clone repo to /whatever/path
cd /whatever/path
git clone http://gitlab.rm-rf.ch/world/openssl_encrypt.git
cd ./openssl_encrypt
```
## Debian
```
sudo apt install python2-minimal
mkvirtualenv -p $(which python2) ./venv
. venv/bin/activate
pip install scrypt
# try if script would run
python2 /path/whatever/openssl_encrypt/helper/opensslCrypt.py
deactivate
```

## Fedora / Centos / Redhat
```
sudo dnf install /usr/bin/virtualenv python2.7
virtualenv --python /usr/bin/python2.7 ./venv
. venv/bin/activate
# should not be necessary
pip install scrypt
# try if script would run
python2 /path/whatever/openssl_encrypt/helper/opensslCrypt.py
deactivate 
```
### Enrypt 
```
cd /whatever/path/openssl_encrypt
. venv/bin/activate
python2 ./helper/opensslCrypt.py -f /path/to/file -d whirlpool -c chacha20 -r 10000 -s 600 -k 448 -i enc
```
this will encrypt `/path/to/file` with the parameters provided. Passwort will be queried vy CLI. Take care that the file will be encrypted and replaced. Therefore test with un-important files first!!
### Decrypt 
```
cd /whatever/path/openssl_encrypt
. venv/bin/activate
python2 ./helper/opensslCrypt.py -f /path/to/file -d whirlpool -c chacha20 -r 10000 -s 600 -k 448 -i dec-write
```
this will decrypt `/path/to/file` with parameters provided. Passwort will be queried vy CLI. Decrypted file will overwrite the enrypted one. For small TXT files that you want to keep encrypted it's possible to not overwrite but just show decrypted content on CLI
```
cd /whatever/path/openssl_encrypt
. venv/bin/activate
python2 ./helper/opensslCrypt.py -f /path/to/file -d whirlpool -c chacha20 -r 10000 -s 600 -k 448 -i dec
```
this will just print decrypted content but keep the file encrypted on disk.

Possible values for the parameters can be seen with the bash Wrapper
```
crypt.sh ACTION -f|--file -p|--pass [[-c|--cipher] blowfish] [[-d|--digest] sha256] [[-r|--rounds 1] [-s|--scrypt 0] [[-k|--keysize] 256] [--quiet] [--verbose] [--show] [--force]
    Positional ACTION  argument is mandatory and must be the first argument
    Possible values for ACTION$ are: enc|dec|dec-write|dec-disp
  WARNING: the enc parameter encrypts FILE and overwrites the unencrypted file with the crypted content
  Most command line switches are optional. The following switches are recognized
    -f|--file    <string>    --file to perform ACTION on
                               mandatory, no default
    -p|--pass    <string>    --password to use as key for encryption
                               mandatory, no default
    -c|--cipher  <string>    --cipher to use for encryption
                               not mandatory, blowfish
    -d|--digest  <string>    --digest to use for file content hashing and for hashing the password with
                               not mandatory, sha256
    -k|--keysize <string>    --size of the encryption key to generate in bits
                               not mandatory, 256
    -r|--rounds  <integer>   --number of rounds to apply digest to the password
                               not mandatory, 1
    -s|--scrypt  <integer>   --use scrypt for password hashing as well. run hash function X times
                               not mandatory, 0
    -h|--help    <NONE>      --displays this help message
                               not mandatory
    -v|--version <NONE>      --shows version information
                               not mandatory
    --show       <NONE>      --show available ciphers from openssl
                               not mandatory
    --force      <NONE>      --enforces decryption even if the decryptet content looks compromised
                               not mandatory
    --quiet      <integer>   --supress ANY output if set to 1. Just exit with return codes. Helpful for scripts
                               If set to 0 it allows only output of dencrypted file
                               Any exit value except 0 can be considered an error. Overrides --verbose!
                               not mandatory
    --verbose    <NONE>      --be more verbose by printing INFO messages
                               Has no effect if --quiet is set
                               not mandatory
```
`cipher` and `digest` should support any value that your `openssl` is aware of or use `--show` to see supported ciphers
