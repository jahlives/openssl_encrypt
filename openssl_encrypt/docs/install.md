## Installation

### Requirements

- Python 3.6 or higher
- Dependencies: cryptography (required), pywhirlpool (optional), tkinter (for GUI)

### Setup

1. Clone or download this repository
2. Install required packages:

```bash
pip install -r requirements.txt
```

For Argon2 support:

```bash
pip install argon2-cffi
```
### Testing
After installation I highly recommend to run the unitests first. \
Although they're also run when I commit, it's always perferable to verify that\
locally before encrypting important files. Better safe than sorry ;-)
```bash
pip install pytest
pytest unittests/unittests.pytest
```
They all must pass or [else open an issue here](mailto:tobster+world-openssl-encrypt-2-issue-+gitlab@brain-force.ch) :-) \
Another recommendation is to avoid the `--overwrite` parameter first when encrypting \
and verify first that the file can be decrypted