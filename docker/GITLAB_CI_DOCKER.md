# GitLab CI Docker Build Pipeline

This document explains how to use the `.gitlab-ci-build.yml` pipeline for building and publishing Docker containers with full PQC support.

## Overview

The Docker CI pipeline automatically builds, tests, and publishes Docker containers containing your openssl_encrypt tool with complete Post-Quantum Cryptography support including:

- **73+ PQC algorithms** (ML-KEM, Kyber, HQC, etc.)
- **liboqs 0.12.0** with Python bindings
- **Multi-stage optimized build** (~200MB runtime image)
- **All dependencies included** (no external setup required)

## Pipeline Stages

### 1. Docker Build (`docker-build`)
- Builds the Docker image using the `docker/Dockerfile`
- Uses BuildKit for optimization and caching
- Tags images with commit SHA and branch/tag names
- Pushes to GitLab Container Registry

### 2. Docker Test (`docker-test`)
- Tests basic CLI functionality
- Verifies PQC algorithm availability
- Performs actual encryption/decryption test
- Validates liboqs integration

### 3. Docker Publish (`docker-publish`)
- Publishes release images for tags and main branch
- Updates `latest` and `stable` tags
- Provides usage instructions

## Usage

### Using the Dedicated Pipeline

1. **Copy the pipeline file to your GitLab project:**
   ```bash
   cp .gitlab-ci-build.yml .gitlab-ci.yml
   ```

2. **Or include it in your existing pipeline:**
   ```yaml
   # Add to your existing .gitlab-ci.yml
   include:
     - local: '.gitlab-ci-build.yml'
   ```

### Triggering Builds

The pipeline automatically runs on:
- ✅ **Main branch commits** - builds and publishes `latest` tag
- ✅ **Release branch commits** - builds with manual publish step
- ✅ **Git tags** - builds and publishes `stable` and version tags
- ✅ **Dev branch commits** - builds for testing
- ✅ **Merge requests** - builds for validation

### Manual Triggers

- **Rebuild on dev/testing**: Use the `docker-rebuild` manual job
- **Cleanup old images**: Use the `docker-cleanup` manual job

## Image Tags

The pipeline creates several image tags:

| Tag Pattern | Description | When Created |
|-------------|-------------|--------------|
| `registry.gitlab.com/user/project/openssl-encrypt:latest` | Latest stable build | Main branch |
| `registry.gitlab.com/user/project/openssl-encrypt:stable` | Latest release | Git tags |
| `registry.gitlab.com/user/project/openssl-encrypt:v1.0.0` | Specific version | Git tags |
| `registry.gitlab.com/user/project/openssl-encrypt:main` | Branch-specific | Branch commits |
| `registry.gitlab.com/user/project/openssl-encrypt:abc1234` | Commit SHA | All commits |

## Using Built Images

### Pull from GitLab Registry

```bash
# Latest version
docker pull registry.gitlab.com/youruser/openssl_encrypt/openssl-encrypt:latest

# Specific version
docker pull registry.gitlab.com/youruser/openssl_encrypt/openssl-encrypt:v0.9.2
```

### Basic Usage

```bash
# Help
docker run --rm registry.gitlab.com/youruser/openssl_encrypt/openssl-encrypt:latest --help

# Encrypt with PQC
docker run --rm -v $(pwd):/data \
  registry.gitlab.com/youruser/openssl_encrypt/openssl-encrypt:latest \
  encrypt --input myfile.txt --algorithm kyber768-hybrid --password 'MyPassword123!'

# Decrypt
docker run --rm -v $(pwd):/data \
  registry.gitlab.com/youruser/openssl_encrypt/openssl-encrypt:latest \
  decrypt --input myfile.txt --password 'MyPassword123!'
```

## Configuration Variables

Set these in GitLab CI/CD Settings → Variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `CI_REGISTRY_USER` | GitLab registry username | Auto-set |
| `CI_REGISTRY_PASSWORD` | GitLab registry password | Auto-set |
| `CI_REGISTRY` | GitLab registry URL | Auto-set |

## Customization

### Modify Build Context

```yaml
variables:
  DOCKERFILE_PATH: docker/Dockerfile  # Path to Dockerfile
  BUILD_CONTEXT: .                    # Build context directory
```

### Add Custom Build Args

```yaml
# In docker-build job script section
docker build \
  --build-arg LIBOQS_VERSION=0.12.0 \
  --build-arg PYTHON_VERSION=3.11 \
  -f $DOCKERFILE_PATH \
  -t $DOCKER_IMAGE_NAME:$CI_COMMIT_SHA \
  $BUILD_CONTEXT
```

### Additional Registries

Add steps to push to Docker Hub or other registries:

```yaml
# Add to docker-publish job
- echo $DOCKERHUB_PASSWORD | docker login -u $DOCKERHUB_USERNAME --password-stdin
- docker tag $DOCKER_IMAGE_NAME:$CI_COMMIT_SHA youruser/openssl-encrypt:$CI_COMMIT_TAG
- docker push youruser/openssl-encrypt:$CI_COMMIT_TAG
```

## Troubleshooting

### Build Failures

1. **Docker daemon issues:**
   - Check GitLab Runner has Docker-in-Docker capability
   - Verify `privileged = true` in runner config

2. **Registry authentication:**
   - Ensure CI/CD variables are set correctly
   - Check registry permissions

3. **Build timeout:**
   - Increase job timeout in GitLab project settings
   - Optimize Dockerfile for faster builds

### Test Failures

1. **PQC tests fail:**
   - Verify liboqs version compatibility
   - Check that both C library and Python bindings are installed

2. **CLI tests fail:**
   - Verify entrypoint configuration
   - Check Python module paths

### Performance Optimization

1. **Use build cache:**
   ```yaml
   --cache-from $DOCKER_IMAGE_NAME:cache
   ```

2. **Parallel builds:**
   - Use BuildKit features
   - Split complex RUN commands

3. **Registry caching:**
   - Store intermediate layers
   - Use multi-stage builds effectively

## Security Considerations

- ✅ **Non-root user** - Container runs as `crypt` user
- ✅ **Minimal base image** - Uses `python:3.11-slim`
- ✅ **No secrets in layers** - Build args cleaned up
- ✅ **Registry scanning** - Enable container scanning in GitLab
- ✅ **Signed images** - Consider using `docker trust` for production

## Monitoring

Monitor your builds in:
- **GitLab CI/CD → Pipelines** - Pipeline status and logs
- **GitLab Packages → Container Registry** - Published images
- **GitLab Security → Dependency Scanning** - Security reports (if enabled)

## Integration Examples

### GitHub Actions (for cross-platform)

```yaml
- name: Pull and test
  run: |
    docker pull registry.gitlab.com/youruser/openssl_encrypt/openssl-encrypt:latest
    docker run --rm registry.gitlab.com/youruser/openssl_encrypt/openssl-encrypt:latest --help
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openssl-encrypt
spec:
  template:
    spec:
      containers:
      - name: openssl-encrypt
        image: registry.gitlab.com/youruser/openssl_encrypt/openssl-encrypt:stable
        command: ["openssl-encrypt"]
        args: ["--help"]
```

## Next Steps

1. **Set up the pipeline** by copying `.gitlab-ci-build.yml`
2. **Test the build** by pushing to your GitLab repository
3. **Customize tags** and publishing rules as needed
4. **Monitor builds** and optimize for your workflow
5. **Add security scanning** if not already enabled
