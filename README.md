# openssl-crypt

Bash Wrapper for encrypting and decrypting files via `openssl`. It uses a `python` script in the background and requires `python 2.x` so on modern systems a `venv` is needed.

## Debian
```
# clone repo to /whatever/path
cd /whatever/path
sudo apt install python2-minimal
sudo mkvirtualenv -p $(which python2) ./venv
. venv/bin/activate
pip install scrypt
# try if script would run
python2 /path/whatever/helper/opensslCrypt.py
deactivate
```

## Fedora / Centos / Redhat
```
sudo dnf install python2-virtualenv
cd /whatever/path
sudo virtualenv2 ./venv
. venv/bin/activate
pip install scrypt
# try if script would run
python2 /path/whatever/helper/opensslCrypt.py
deactivate 
```
