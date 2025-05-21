# CI Pipeline Security Scanning

This document describes the automated security scanning that is integrated into the CI/CD pipeline for the openssl_encrypt project.

## Overview

Security scanning is performed automatically as part of the Continuous Integration (CI) pipeline. These checks help identify security vulnerabilities before they reach production. The pipeline includes three main security checks:

1. **Dependency Scanning**: Checks all dependencies for known vulnerabilities
2. **Code Security Scanning**: Performs static analysis on the codebase to identify security issues
3. **Software Bill of Materials (SBOM)**: Generates a detailed inventory of all components

## CI Pipeline Configuration

The security scanning jobs are defined in `.gitlab-ci.yml` and run in the `security` stage, which happens before the test, build, and publish stages. This ensures that security issues are caught early in the pipeline.

### When Security Scanning Runs

Security scanning is automatically run on:
- All commits to the `main`, `dev`, and `release` branches
- All merge requests

## Dependency Scanning

The dependency scanning job checks for known vulnerabilities in both production and development dependencies.

### How It Works

1. The job uses the `safety` tool to scan dependencies listed in:
   - `requirements-prod.txt` (production dependencies)
   - `requirements-dev.txt` (development dependencies)
2. Results are displayed in the job output and saved as JSON reports
3. GitLab integrates these reports into the Security Dashboard

### Interpreting Results

Vulnerabilities are organized by severity (high, medium, low):

```
+==============================================================================+
|                                                                              |
|                               SAFETY REPORT                                  |
|                                                                              |
+=========================+===============+==========+======================+=============+
| package                 | installed     | affected | vulnerability        | severity    |
+=========================+===============+==========+======================+=============+
| cryptography            | 44.0.3        | <45.0.0  | CVE-2024-XXXXX       | Medium      |
+=========================+===============+==========+======================+=============+
```

## Code Security Scanning

Static Analysis Security Testing (SAST) is performed on the Python codebase to identify potential security issues in the code.

### How It Works

1. The job uses the `bandit` tool to scan the Python code
2. Custom rules are defined in `.bandit.yaml`
3. Specific checks for cryptographic code are included
4. Results are displayed in the job output and saved as JSON reports

### Interpreting Results

Bandit issues include:
- Issue type (e.g., hardcoded password, unsafe deserialization)
- Severity (high, medium, low)
- Confidence level
- File location

Example output:
```
>> Issue: [B506:yaml_load] Use of unsafe yaml load. Allows instantiation of arbitrary objects.
   Severity: High   Confidence: High
   Location: openssl_encrypt/modules/crypt_utils.py:123
```

## Software Bill of Materials (SBOM)

An SBOM is generated during the CI process, providing a comprehensive inventory of all components in the software.

### How It Works

1. The job uses the `cyclonedx-bom` tool to generate an SBOM in CycloneDX format
2. The SBOM is saved as a JSON file and attached to the job as an artifact
3. The SBOM can be used for compliance, vulnerability tracking, and license management

### SBOM Contents

The SBOM includes:
- All direct and transitive dependencies
- Version information
- License information
- Package URLs (PURLs)
- Component types

## Viewing Scan Results

### In GitLab

1. Navigate to your project in GitLab
2. Go to "Security & Compliance" in the left sidebar
3. Select "Vulnerability Report" to see all detected vulnerabilities
4. For specific job results, go to CI/CD > Pipelines > select a pipeline > view the security jobs

### In Pipeline Artifacts

Each security job produces artifacts that can be downloaded for further analysis:
- `gl-dependency-scanning-report.json` - Dependency scan results
- `gl-sast-report.json` - Code security scan results
- `bom.json` - Software Bill of Materials

## Handling Security Findings

### Process for Addressing Issues

1. **Triage**: Evaluate each finding for validity, severity, and impact
2. **Prioritize**: Address high-severity issues first
3. **Fix**: Make the necessary changes to address the issue
4. **Verify**: Run scans locally to confirm the issue is resolved
5. **Document**: Record the fix in the commit message and CHANGELOG.md

### False Positives

If you believe a finding is a false positive:
1. Document your reasoning in a comment near the code in question
2. Update the configuration to exclude specific false positives if necessary
3. Never ignore security warnings without proper documentation

## Local Testing

You can run the same security checks locally before pushing changes:

```bash
# Install the required tools
pip install safety bandit cyclonedx-bom

# Run dependency scanning
safety scan -r requirements-prod.txt --output text

# Run code security scanning
bandit -r openssl_encrypt/ -c .bandit.yaml

# Generate SBOM
cyclonedx-py -r -i requirements-prod.txt -o bom.json
```

## Additional Resources

- [Safety Documentation](https://pyup.io/safety/docs/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [CycloneDX Documentation](https://cyclonedx.org/)
- [GitLab Security Dashboard](https://docs.gitlab.com/ee/user/application_security/security_dashboard/)