from setuptools import setup, find_packages

setup(
    name="openssl_encrypt",
    version="1.0.1",
    packages=find_packages(),
    install_requires=[
        # List your dependencies here, for example:
        # "cryptography>=3.4.0",
    ],
    author="Tobi",
    author_email="jahlives@gmx.ch",
    description="A package for secure file encryption and decryption based on modern ciphers",
    keywords="encryption, openssl, security",
    url="https://gitlab.com/world/openssl_encrypt",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.6",
)
