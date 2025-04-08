from setuptools import setup, find_packages
import os

# Read the contents of your README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="openssl_encrypt",
    version="0.2.2",
    install_requires=[
        "cryptography>=42.0.0",
        "argon2-cffi>=23.1.0",
        "bcrypt~=4.3.0",
        "pywin32>=306; sys_platform == 'win32'",  # Windows-specific dependency
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=4.1.0",
            "black>=24.1.0",
            "pylint>=3.0.0",
        ],
    },
    packages=find_packages(),
    include_package_data=True,
    author="Tobi",
    author_email="jahlives@gmx.ch",
    description="A package for secure file encryption and decryption based on modern ciphers",
    long_description=long_description,
    long_description_content_type="text/markdown",
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
