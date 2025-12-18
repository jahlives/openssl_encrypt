# Multi-stage Dockerfile for openssl_encrypt with full PQC support
# This dockerfile builds a complete image with liboqs and all post-quantum cryptography support

# Stage 1: Build environment with all development tools
FROM python:3.11-slim as builder

# Install build dependencies (based on your pqc.md documentation)
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    pkg-config \
    ninja-build \
    golang \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python build dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Set working directory for builds
WORKDIR /build

# Build and install liboqs C library (following your pqc.md documentation)
# Use version 0.12.0 to match Python bindings
RUN git clone --recurse-submodules --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
WORKDIR /build/liboqs
RUN mkdir build && cd build && \
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=ON \
        .. && \
    ninja && \
    ninja install

# Set library path for runtime
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
RUN ldconfig

# Install Python bindings from GitHub (following your pqc.md documentation)
# Use matching version 0.12.0
RUN pip install --no-cache-dir git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0

# Copy source code for openssl_encrypt
COPY . /build/openssl_encrypt
WORKDIR /build/openssl_encrypt

# Install openssl_encrypt with all dependencies
RUN pip install --no-cache-dir -e ".[dev]"

# Stage 2: Runtime environment (smaller final image)
FROM python:3.11-slim as runtime

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs library from builder
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs

# Update library cache
RUN ldconfig

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/openssl-encrypt /usr/local/bin/
COPY --from=builder /usr/local/bin/whirlpool-setup /usr/local/bin/

# Copy openssl_encrypt source code since it was installed in editable mode
COPY --from=builder /build/openssl_encrypt/openssl_encrypt /usr/local/lib/python3.11/site-packages/openssl_encrypt

# Set environment variables for runtime
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

# Fix Python path for root-installed packages
RUN ldconfig

# Create a non-root user for security
RUN useradd --create-home --shell /bin/bash crypt && \
    mkdir -p /data && \
    chown crypt:crypt /data

# Fix whirlpool permissions - create the symlink as root before switching users
RUN cd /usr/local/lib/python3.11/site-packages && \
    if [ -f whirlpool-py311.cpython-311-x86_64-linux-gnu.so ]; then \
        ln -sf whirlpool-py311.cpython-311-x86_64-linux-gnu.so whirlpool.cpython-311-x86_64-linux-gnu.so; \
    fi

# Make Python packages readable by crypt user
RUN chown -R root:root /usr/local/lib/python3.11/site-packages && \
    chmod -R 755 /usr/local/lib/python3.11/site-packages

# Set working directory to /data for file operations
WORKDIR /data

# Switch to non-root user
USER crypt

# Verify installation and PQC support
RUN python -c "from openssl_encrypt.modules.pqc_liboqs import check_liboqs_support; \
    available, version, algorithms = check_liboqs_support(quiet=True); \
    print(f'liboqs available: {available}, version: {version}, algorithms: {len(algorithms)}')" || true

# Set the entrypoint to openssl-encrypt
ENTRYPOINT ["openssl-encrypt"]

# Default command shows help
CMD ["--help"]
