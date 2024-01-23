# openssl-crypt

Bash Wrapper for encrypting and decrypting files via `openssl`. It uses a `python` script in the background and requires `python 2.x` so on modern systems a `venv` is needed.

## All
```
# clone repo to /whatever/path
cd /whatever/path
git clone http://gitlab.rm-rf.ch/world/openssl_encrypt.git
sudo apt install python2-minimal
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
