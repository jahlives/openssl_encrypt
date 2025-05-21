# Dependency Management Guide

This document outlines the dependency management strategy for the openssl_encrypt project. It explains how dependencies are tracked, updated, and maintained throughout the project lifecycle.

## Dependency Structure

The project uses a structured approach to dependency management:

1. **Source `.in` Files**:
   - `requirements-prod.in`: Contains production dependencies with version constraints
   - `requirements-dev.in`: Contains development dependencies, includes production dependencies

2. **Lock `.txt` Files**:
   - `requirements-prod.txt`: Precisely pinned production dependencies
   - `requirements-dev.txt`: Precisely pinned development dependencies

3. **Build Configuration**:
   - `pyproject.toml`: Contains build dependencies
   - `setup.py`: Contains installation dependencies

## Using the Lock Files

### For Development

To install all development dependencies:

```bash
pip install -r requirements-dev.txt
```

### For Production

To install only production dependencies:

```bash
pip install -r requirements-prod.txt
```

## Updating Dependencies

We use pip-tools to manage dependencies efficiently. A script is provided to simplify the update process:

```bash
# Run the update script
scripts/update_dependencies.sh
```

You can also manually update dependencies:

1. Edit the `.in` files with new dependency constraints
2. Generate updated lock files:
   ```bash
   pip-compile requirements-prod.in --output-file=requirements-prod.txt
   pip-compile requirements-dev.in --output-file=requirements-dev.txt
   ```
3. Sync your environment:
   ```bash
   pip-sync requirements-dev.txt
   ```

## Version Pinning Strategy

### In Source Files (`.in`)

- **Security-critical dependencies**: Use both lower and upper bounds
  - Example: `cryptography>=44.0.1,<45.0.0`
  
- **Regular dependencies**: Use compatible release specification
  - Example: `bcrypt~=4.3.0` (allows 4.3.*)

- **Development tools**: Use minimum version with upper bounds
  - Example: `pytest>=8.0.0,<9.0.0`

### In Lock Files (`.txt`)

All dependencies are pinned to exact versions to ensure reproducibility.

## Dependency Update Workflow

1. **Regular Schedule**:
   - Security-critical dependencies: Check weekly
   - All dependencies: Update monthly

2. **Vulnerability Alerts**:
   - Address critical vulnerabilities immediately
   - Test thoroughly before merging

3. **Update Process**:
   - Run `scripts/update_dependencies.sh`
   - Verify tests pass with new dependencies
   - Commit updated lock files
   - Document significant changes in `CHANGELOG.md`

4. **Breaking Changes**:
   - Document in pull request
   - Update code to accommodate breaking API changes
   - Include comprehensive tests

## Using Dependency Files with CI/CD

In your CI/CD pipeline, use the lock files to ensure consistent builds:

```yaml
# Example CI config snippet
steps:
  - name: Install dependencies
    run: pip install -r requirements-prod.txt  # For production builds
    # OR
    run: pip install -r requirements-dev.txt   # For development builds including tests
```

## Security Considerations

- Lock files prevent unexpected dependency changes
- Regular updates ensure security patches are applied
- Pinned major/minor versions prevent breaking changes
- The security scanning pipeline will validate dependencies against known vulnerabilities