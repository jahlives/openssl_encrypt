# GitLab CI/CD Configuration

This directory contains configuration for GitLab CI/CD pipelines and schedules.

## Scheduled Pipelines

The `schedules.yml` file contains configurations for scheduled pipelines. To set up a scheduled pipeline:

1. Go to your GitLab project
2. Navigate to Build > Pipelines > Schedules
3. Click "New schedule"
4. Use the configurations from the `schedules.yml` file to set up your schedules

## Docker Images

The CI/CD pipeline uses custom Docker images to speed up the build process. The main image contains:

- Python 3.13 on Alpine Linux
- liboqs (Open Quantum Safe library) pre-installed
- Common dependencies for testing

### Building the Docker Image Manually

To manually trigger a build of the Docker image:

1. Go to your GitLab project
2. Navigate to Build > Pipelines
3. Click "Run pipeline"
4. Select the branch (typically "dev")
5. Add a variable:
   - Key: `BUILD_DOCKER_IMAGE`
   - Value: `true`
6. Click "Run pipeline"

The image will be built and pushed to your GitLab Container Registry.