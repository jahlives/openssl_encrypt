"""HSM (Hardware Security Module) plugins for OpenSSL Encrypt.

Note: This __init__.py is intentionally minimal to avoid being discovered
as a plugin itself. The actual plugins are in the subdirectories:
- yubikey_challenge_response/
- fido2_pepper/
"""

# Do NOT import plugins here, as this __init__.py gets discovered as a plugin package
# and the plugin manager can only register one plugin class per module.
# The subdirectories are discovered and loaded separately.
