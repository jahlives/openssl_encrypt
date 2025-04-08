from setuptools import setup, find_packages
import os

# Read the contents of your README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="openssl_encrypt",
    version="1.1.0",
    install_requires=[
        # List your dependencies here, for example:
        # "cryptography>=3.4.0",
    ],
    packages=find_packages(exclude=["__pycache__", "*.pyc"]),
    include_package_data=True,
    author="Tobi",
    author_email="jahlives@gmx.ch",
    description="A package for secure file encryption and decryption based on modern ciphers",
    keywords="encryption, openssl, security",
    long_description=long_description,
    url="https://gitlab.com/world/openssl_encrypt",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.6",
)
