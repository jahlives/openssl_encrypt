# Multi-stage build for OpenSSL Encrypt Server
# Stage 1: Build liboqs (PQC library)
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    ninja-build \
    libssl-dev \
    libssl3 \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs
WORKDIR /tmp
RUN git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=ON \
        .. && \
    ninja && \
    ninja install

# Build liboqs-python
RUN git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && \
    pip install --no-cache-dir . && \
    python -c "import oqs; print('liboqs-python version:', oqs.oqs_version())"

# Stage 2: Runtime image
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs from builder
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs

# Copy liboqs-python from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages/oqs /usr/local/lib/python3.11/site-packages/oqs

RUN ldconfig

# Create app user
RUN useradd -m -u 1000 appuser

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . ./openssl_encrypt_server/

# Change ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run server
CMD ["python", "-m", "uvicorn", "openssl_encrypt_server.server:app", "--host", "0.0.0.0", "--port", "8080"]
