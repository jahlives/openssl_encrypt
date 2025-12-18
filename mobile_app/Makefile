# Makefile for building Python FFI shared library for OpenSSL Encrypt Mobile

# Python configuration
PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_INCLUDE := $(shell python3 -c "import sysconfig; print(sysconfig.get_path('include'))")
PYTHON_LIB := $(shell python3 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
PYTHON_LDFLAGS := $(shell python3 -config --ldflags --embed 2>/dev/null || python3 -config --ldflags)

# Compiler settings
CC = clang
CFLAGS = -fPIC -shared -O2 -Wall
INCLUDES = -I$(PYTHON_INCLUDE)
LDFLAGS = $(PYTHON_LDFLAGS)

# Target library
TARGET = libcrypto_ffi.so
SOURCE = crypto_ffi_wrapper.c

# Default target
all: $(TARGET)

# Build shared library
$(TARGET): $(SOURCE)
	@echo "Building Python FFI library..."
	@echo "Python version: $(PYTHON_VERSION)"
	@echo "Python include: $(PYTHON_INCLUDE)"
	@echo "Python lib: $(PYTHON_LIB)"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)
	@echo "✅ Built $(TARGET) successfully"

# Test the library
test: $(TARGET)
	@echo "Testing Python crypto core..."
	python3 mobile_crypto_core.py
	@echo "Testing FFI library..."
	python3 -c "import ctypes; lib = ctypes.CDLL('./$(TARGET)'); print('✅ FFI library loaded successfully')"

# Clean build artifacts
clean:
	rm -f $(TARGET)
	@echo "Cleaned build artifacts"

# Install dependencies
deps:
	@echo "Installing Python dependencies..."
	pip3 install --user cryptography

# Show configuration
config:
	@echo "Build Configuration:"
	@echo "  CC: $(CC)"
	@echo "  Python Version: $(PYTHON_VERSION)"
	@echo "  Python Include: $(PYTHON_INCLUDE)"
	@echo "  Python Lib: $(PYTHON_LIB)"
	@echo "  CFLAGS: $(CFLAGS)"
	@echo "  INCLUDES: $(INCLUDES)"
	@echo "  LDFLAGS: $(PYTHON_LDFLAGS)"

.PHONY: all test clean deps config
