#!/usr/bin/env python3
"""
Security Audit Report Generator for OpenSSL Encrypt

This module provides tools for analyzing security audit logs and generating
reports for forensic analysis and compliance auditing.

Usage:
    # Generate a security report
    python -m openssl_encrypt.modules.security_report

    # Analyze specific time period
    python -m openssl_encrypt.modules.security_report --hours 48

    # Show only critical events
    python -m openssl_encrypt.modules.security_report --severity critical

    # Export to JSON format
    python -m openssl_encrypt.modules.security_report --format json
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .security_logger import get_security_logger


class SecurityReportGenerator:
    """
    Generate security audit reports from audit logs.
    """

    def __init__(self):
        self.security_logger = get_security_logger()

    def generate_report(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        format: str = "text"
    ) -> str:
        """
        Generate a security audit report.

        Args:
            hours: Number of hours to look back (default: 24)
            severity: Filter by severity level (optional)
            event_type: Filter by event type (optional)
            format: Output format ("text" or "json")

        Returns:
            Formatted report string
        """
        # Retrieve events
        events = self.security_logger.get_recent_events(
            hours=hours,
            event_type=event_type,
            severity=severity
        )

        if not events:
            return "No security events found in the specified time period."

        if format == "json":
            return self._generate_json_report(events)
        else:
            return self._generate_text_report(events, hours, severity, event_type)

    def _generate_text_report(
        self,
        events: List[dict],
        hours: int,
        severity: Optional[str],
        event_type: Optional[str]
    ) -> str:
        """Generate human-readable text report."""
        lines = []
        lines.append("=" * 80)
        lines.append("SECURITY AUDIT REPORT - OpenSSL Encrypt".center(80))
        lines.append("=" * 80)
        lines.append("")

        # Report metadata
        lines.append(f"Report Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Time Period: Last {hours} hours")
        if severity:
            lines.append(f"Severity Filter: {severity}")
        if event_type:
            lines.append(f"Event Type Filter: {event_type}")
        lines.append(f"Total Events: {len(events)}")
        lines.append("")

        # Event statistics
        lines.append("-" * 80)
        lines.append("EVENT STATISTICS")
        lines.append("-" * 80)

        # Count by event type
        event_counts = Counter(e['event_type'] for e in events)
        lines.append("\nEvents by Type:")
        for evt_type, count in event_counts.most_common():
            lines.append(f"  {evt_type:.<50} {count:>5}")

        # Count by severity
        severity_counts = Counter(e['severity'] for e in events)
        lines.append("\nEvents by Severity:")
        for sev, count in severity_counts.most_common():
            lines.append(f"  {sev:.<50} {count:>5}")

        # Count by user
        user_counts = Counter(e.get('user', 'unknown') for e in events)
        lines.append("\nEvents by User:")
        for user, count in user_counts.most_common():
            lines.append(f"  {user:.<50} {count:>5}")

        # Security concerns
        lines.append("")
        lines.append("-" * 80)
        lines.append("SECURITY CONCERNS")
        lines.append("-" * 80)

        # Critical events
        critical_events = [e for e in events if e['severity'] == 'critical']
        if critical_events:
            lines.append(f"\n⚠️  CRITICAL: {len(critical_events)} critical security events detected!")
            lines.append("")
            for event in critical_events[:10]:  # Show first 10
                lines.append(f"  [{event['timestamp']}] {event['event_type']}")
                if 'details' in event:
                    for key, value in event['details'].items():
                        lines.append(f"    {key}: {value}")
                lines.append("")
            if len(critical_events) > 10:
                lines.append(f"  ... and {len(critical_events) - 10} more critical events")
        else:
            lines.append("\n✓ No critical security events detected")

        # Warning events
        warning_events = [e for e in events if e['severity'] == 'warning']
        if warning_events:
            lines.append(f"\n⚠️  {len(warning_events)} warning events detected")

            # Group warnings by type
            warning_types = defaultdict(list)
            for event in warning_events:
                warning_types[event['event_type']].append(event)

            for evt_type, evt_list in sorted(warning_types.items(), key=lambda x: len(x[1]), reverse=True):
                lines.append(f"\n  {evt_type}: {len(evt_list)} occurrences")
                # Show first 3 examples
                for event in evt_list[:3]:
                    lines.append(f"    [{event['timestamp']}]")
                    if 'details' in event:
                        for key, value in list(event['details'].items())[:3]:
                            lines.append(f"      {key}: {value}")
                if len(evt_list) > 3:
                    lines.append(f"    ... and {len(evt_list) - 3} more")
        else:
            lines.append("\n✓ No warning events detected")

        # Operational summary
        lines.append("")
        lines.append("-" * 80)
        lines.append("OPERATIONAL SUMMARY")
        lines.append("-" * 80)

        # Encryption/decryption operations
        encryption_completed = len([e for e in events if e['event_type'] == 'encryption_completed'])
        decryption_completed = len([e for e in events if e['event_type'] == 'decryption_completed'])
        encryption_failed = len([e for e in events if e['event_type'] == 'encryption_failed'])
        decryption_failed = len([e for e in events if e['event_type'] == 'decryption_failed'])
        auth_failed = len([e for e in events if e['event_type'] == 'decryption_auth_failed'])

        lines.append(f"\nSuccessful Operations:")
        lines.append(f"  Encryptions: {encryption_completed}")
        lines.append(f"  Decryptions: {decryption_completed}")

        if encryption_failed or decryption_failed:
            lines.append(f"\nFailed Operations:")
            if encryption_failed:
                lines.append(f"  Encryptions: {encryption_failed}")
            if decryption_failed:
                lines.append(f"  Decryptions: {decryption_failed}")

        if auth_failed:
            lines.append(f"\nAuthentication Failures: {auth_failed}")
            lines.append("  (Possible brute-force attempts or forgotten passwords)")

        # Plugin events
        plugin_events = [e for e in events if 'plugin' in e['event_type']]
        if plugin_events:
            lines.append(f"\nPlugin Activity:")
            plugin_loaded = len([e for e in plugin_events if e['event_type'] == 'plugin_loaded'])
            plugin_blocked = len([e for e in plugin_events if e['event_type'] == 'plugin_blocked'])
            if plugin_loaded:
                lines.append(f"  Plugins Loaded: {plugin_loaded}")
            if plugin_blocked:
                lines.append(f"  Plugins Blocked: {plugin_blocked} ⚠️")

        # Path security events
        path_events = [e for e in events if 'path' in e['event_type'] or 'blocked' in e['event_type']]
        if path_events:
            lines.append(f"\nPath Security Events:")
            lines.append(f"  Total: {len(path_events)}")
            for event in path_events[:5]:
                lines.append(f"    [{event['event_type']}] {event.get('details', {}).get('requested_path', 'N/A')}")

        # Rate limiting
        rate_limit_events = [e for e in events if e['event_type'] == 'rate_limit_exceeded']
        if rate_limit_events:
            lines.append(f"\nRate Limiting:")
            lines.append(f"  Events: {len(rate_limit_events)}")
            lines.append("  (D-Bus service may be under heavy load)")

        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT".center(80))
        lines.append("=" * 80)

        return "\n".join(lines)

    def _generate_json_report(self, events: List[dict]) -> str:
        """Generate machine-readable JSON report."""
        # Count statistics
        event_counts = Counter(e['event_type'] for e in events)
        severity_counts = Counter(e['severity'] for e in events)
        user_counts = Counter(e.get('user', 'unknown') for e in events)

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "total_events": len(events),
            "statistics": {
                "by_event_type": dict(event_counts),
                "by_severity": dict(severity_counts),
                "by_user": dict(user_counts)
            },
            "critical_events_count": len([e for e in events if e['severity'] == 'critical']),
            "warning_events_count": len([e for e in events if e['severity'] == 'warning']),
            "events": events
        }

        return json.dumps(report, indent=2)

    def get_event_timeline(self, hours: int = 24) -> List[Dict]:
        """
        Get a timeline of security events.

        Args:
            hours: Number of hours to look back

        Returns:
            List of events sorted by timestamp
        """
        events = self.security_logger.get_recent_events(hours=hours)
        return sorted(events, key=lambda e: e['timestamp'])

    def check_for_anomalies(self, hours: int = 24) -> Dict[str, any]:
        """
        Check for security anomalies.

        Args:
            hours: Number of hours to look back

        Returns:
            Dictionary of anomaly findings
        """
        events = self.security_logger.get_recent_events(hours=hours)

        anomalies = {
            "critical_events": [],
            "repeated_auth_failures": [],
            "path_traversal_attempts": [],
            "suspicious_plugin_activity": [],
        }

        # Find critical events
        anomalies["critical_events"] = [
            e for e in events if e['severity'] == 'critical'
        ]

        # Find repeated authentication failures (possible brute-force)
        auth_failures = [e for e in events if e['event_type'] == 'decryption_auth_failed']
        if len(auth_failures) > 5:
            anomalies["repeated_auth_failures"] = auth_failures

        # Find path traversal attempts
        anomalies["path_traversal_attempts"] = [
            e for e in events if e['event_type'] == 'path_traversal_attempt'
        ]

        # Find suspicious plugin activity
        blocked_plugins = [e for e in events if e['event_type'] == 'plugin_blocked']
        if blocked_plugins:
            anomalies["suspicious_plugin_activity"] = blocked_plugins

        return anomalies


def main():
    """Main entry point for security report generator."""
    parser = argparse.ArgumentParser(
        description="Generate security audit reports for OpenSSL Encrypt"
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Number of hours to analyze (default: 24)"
    )
    parser.add_argument(
        "--severity",
        choices=["info", "warning", "critical"],
        help="Filter by severity level"
    )
    parser.add_argument(
        "--event-type",
        help="Filter by specific event type"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--anomalies",
        action="store_true",
        help="Check for security anomalies only"
    )

    args = parser.parse_args()

    # Create report generator
    generator = SecurityReportGenerator()

    if args.anomalies:
        # Check for anomalies
        anomalies = generator.check_for_anomalies(hours=args.hours)

        print("=" * 80)
        print("SECURITY ANOMALY DETECTION".center(80))
        print("=" * 80)
        print()

        has_anomalies = False

        if anomalies["critical_events"]:
            has_anomalies = True
            print(f"⚠️  CRITICAL: {len(anomalies['critical_events'])} critical events detected!")
            for event in anomalies["critical_events"]:
                print(f"  [{event['timestamp']}] {event['event_type']}")

        if anomalies["repeated_auth_failures"]:
            has_anomalies = True
            print(f"\n⚠️  Possible brute-force: {len(anomalies['repeated_auth_failures'])} authentication failures")

        if anomalies["path_traversal_attempts"]:
            has_anomalies = True
            print(f"\n⚠️  Path traversal attempts: {len(anomalies['path_traversal_attempts'])}")

        if anomalies["suspicious_plugin_activity"]:
            has_anomalies = True
            print(f"\n⚠️  Suspicious plugin activity: {len(anomalies['suspicious_plugin_activity'])} blocked plugins")

        if not has_anomalies:
            print("✓ No security anomalies detected")

        print()
        sys.exit(1 if has_anomalies else 0)
    else:
        # Generate full report
        report = generator.generate_report(
            hours=args.hours,
            severity=args.severity,
            event_type=args.event_type,
            format=args.format
        )
        print(report)


if __name__ == "__main__":
    main()
