# Multi-stage build for OpenSSL Encrypt Keyserver

# Stage 1: Build liboqs
FROM python:3.11-slim as liboqs-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    ninja-build \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs
WORKDIR /opt
RUN git clone --depth 1 --branch 0.10.0 https://github.com/open-quantum-safe/liboqs.git
WORKDIR /opt/liboqs
RUN mkdir build && cd build && \
    cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=ON \
    .. && \
    ninja && \
    ninja install

# Stage 2: Application
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs from builder
COPY --from=liboqs-builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=liboqs-builder /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create non-root user
RUN useradd -m -u 1000 keyserver && \
    chown -R keyserver:keyserver /app

USER keyserver

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health')"

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
