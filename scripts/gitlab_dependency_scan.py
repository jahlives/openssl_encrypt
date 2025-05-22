#!/usr/bin/env python3
"""
GitLab Dependency Scanning Script for openssl_encrypt

This script scans the dependencies of the project for known vulnerabilities
and creates a report compatible with GitLab's dependency scanning feature.
It uses pip-audit, a tool maintained by Google for scanning Python dependencies.
"""

import json
import subprocess
import sys
import datetime
import os

def run_pip_audit(requirements_file):
    """Run pip-audit on a requirements file and return the results"""
    try:
        # Make sure pip-audit is available
        subprocess.run(["pip-audit", "--help"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Installing pip-audit...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pip-audit"], check=True)
    
    # Run pip-audit with JSON output
    try:
        print(f"Scanning dependencies in {requirements_file}...")
        result = subprocess.run(
            ["pip-audit", "-r", requirements_file, "--format", "json"], 
            capture_output=True, 
            text=True,
            check=False
        )
        
        # pip-audit returns non-zero if vulnerabilities are found, which is expected
        if result.stdout:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                print(f"JSON decode error. Output: {result.stdout[:200]}...")
                print(f"Error: {result.stderr}")
                return {"error": f"Invalid JSON output: {result.stdout}"}
        else:
            if "No known vulnerabilities found" in result.stderr:
                print(f"No vulnerabilities found in {requirements_file}")
                return {"vulnerabilities": []}
            return {"error": f"Error running pip-audit: {result.stderr}"}
    except Exception as e:
        print(f"Exception details: {e}")
        return {"error": f"Exception running pip-audit: {str(e)}"}

def create_gitlab_report(prod_results, dev_results):
    """Create a GitLab-compatible dependency scanning report"""
    
    vulnerabilities = []
    
    # Process production dependencies from pip-audit format
    if not isinstance(prod_results, dict) or "error" not in prod_results:
        try:
            # pip-audit provides vulnerabilities grouped by package
            for audit_item in prod_results:
                if not isinstance(audit_item, dict):
                    continue
                
                package_name = audit_item.get("name")
                installed_version = audit_item.get("version")
                
                # Extract vulnerabilities
                vulns = audit_item.get("vulnerabilities", [])
                for vuln in vulns:
                    vuln_id = vuln.get("id", "unknown")
                    description = vuln.get("description", "No description available")
                    severity = "unknown"
                    
                    # Try to extract severity from description/fix
                    if "high" in description.lower():
                        severity = "high"
                    elif "medium" in description.lower():
                        severity = "medium"
                    elif "low" in description.lower():
                        severity = "low"
                    
                    # Build GitLab vulnerability item
                    vulnerabilities.append({
                        "id": f"pip-audit-{vuln_id}",
                        "category": "dependency_scanning",
                        "name": f"Vulnerable dependency: {package_name}",
                        "message": description,
                        "description": description,
                        "severity": severity,
                        "solution": f"Upgrade {package_name} to a non-vulnerable version",
                        "scanner": {"id": "pip-audit", "name": "pip-audit"},
                        "location": {
                            "file": "requirements-prod.txt",
                            "dependency": {
                                "package": {"name": package_name},
                                "version": installed_version
                            }
                        },
                        "identifiers": [
                            {"type": "pip-audit", "name": vuln_id, "value": vuln_id},
                            {"type": "cve", "name": vuln.get("cve_id", ""), "value": vuln.get("cve_id", "")}
                        ]
                    })
        except (AttributeError, TypeError, ValueError, KeyError) as e:
            print(f"Error processing production vulnerabilities: {e}")
    
    # Process development dependencies from pip-audit format
    if not isinstance(dev_results, dict) or "error" not in dev_results:
        try:
            # pip-audit provides vulnerabilities grouped by package
            for audit_item in dev_results:
                if not isinstance(audit_item, dict):
                    continue
                
                package_name = audit_item.get("name")
                installed_version = audit_item.get("version")
                
                # Extract vulnerabilities
                vulns = audit_item.get("vulnerabilities", [])
                for vuln in vulns:
                    vuln_id = vuln.get("id", "unknown")
                    
                    # Skip duplicates
                    if any(v.get("id") == f"pip-audit-{vuln_id}" for v in vulnerabilities):
                        continue
                    
                    description = vuln.get("description", "No description available")
                    severity = "unknown"
                    
                    # Try to extract severity from description/fix
                    if "high" in description.lower():
                        severity = "high"
                    elif "medium" in description.lower():
                        severity = "medium"
                    elif "low" in description.lower():
                        severity = "low"
                    
                    # Build GitLab vulnerability item
                    vulnerabilities.append({
                        "id": f"pip-audit-{vuln_id}",
                        "category": "dependency_scanning",
                        "name": f"Vulnerable dependency: {package_name}",
                        "message": description,
                        "description": description,
                        "severity": severity,
                        "solution": f"Upgrade {package_name} to a non-vulnerable version",
                        "scanner": {"id": "pip-audit", "name": "pip-audit"},
                        "location": {
                            "file": "requirements-dev.txt",
                            "dependency": {
                                "package": {"name": package_name},
                                "version": installed_version
                            }
                        },
                        "identifiers": [
                            {"type": "pip-audit", "name": vuln_id, "value": vuln_id},
                            {"type": "cve", "name": vuln.get("cve_id", ""), "value": vuln.get("cve_id", "")}
                        ]
                    })
        except (AttributeError, TypeError, ValueError, KeyError) as e:
            print(f"Error processing development vulnerabilities: {e}")
    
    # Create GitLab report
    try:
        # Use timezone-aware datetime with UTC
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    except AttributeError:
        # Fallback for older Python versions
        now = datetime.datetime.utcnow().isoformat() + "Z"
        
    report = {
        "version": "14.0.0",
        "vulnerabilities": vulnerabilities,
        "scan": {
            "analyzer": {
                "id": "pip-audit",
                "name": "pip-audit",
                "vendor": {"name": "Google"},
                "version": "2.9.0"
            },
            "scanner": {
                "id": "pip-audit",
                "name": "pip-audit",
                "vendor": {"name": "Google"},
                "version": "2.9.0"
            },
            "type": "dependency_scanning",
            "start_time": now,
            "end_time": now,
            "status": "success"
        }
    }
    
    return report

def main():
    """Main function"""
    # Get the root directory of the project
    project_dir = os.getcwd()
    
    # Run pip-audit on production requirements
    print("Scanning production dependencies...")
    prod_requirements = os.path.join(project_dir, "requirements-prod.txt")
    prod_results = run_pip_audit(prod_requirements)
    
    # Print summary for production dependencies
    if isinstance(prod_results, dict) and "error" in prod_results:
        print(f"Error scanning production dependencies: {prod_results['error']}")
    else:
        try:
            vuln_count = sum(len(pkg.get("vulnerabilities", [])) for pkg in prod_results if isinstance(pkg, dict))
            print(f"Found {vuln_count} vulnerabilities in production dependencies")
        except (AttributeError, TypeError):
            print("Error parsing production scan results")
    
    # Run pip-audit on development requirements
    print("Scanning development dependencies...")
    dev_requirements = os.path.join(project_dir, "requirements-dev.txt")
    dev_results = run_pip_audit(dev_requirements)
    
    # Print summary for development dependencies
    if isinstance(dev_results, dict) and "error" in dev_results:
        print(f"Error scanning development dependencies: {dev_results['error']}")
    else:
        try:
            vuln_count = sum(len(pkg.get("vulnerabilities", [])) for pkg in dev_results if isinstance(pkg, dict))
            print(f"Found {vuln_count} vulnerabilities in development dependencies")
        except (AttributeError, TypeError):
            print("Error parsing development scan results")
    
    # Create GitLab report
    report = create_gitlab_report(prod_results, dev_results)
    
    # Save report to file
    report_path = os.path.join(project_dir, "gl-dependency-scanning-report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"GitLab dependency scanning report saved to {report_path}")
    
    # Also save raw results for debugging
    if not isinstance(prod_results, dict) or "error" not in prod_results:
        with open(os.path.join(project_dir, "pip-audit-prod-results.json"), "w") as f:
            json.dump(prod_results, f, indent=2)
    
    if not isinstance(dev_results, dict) or "error" not in dev_results:
        with open(os.path.join(project_dir, "pip-audit-dev-results.json"), "w") as f:
            json.dump(dev_results, f, indent=2)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())