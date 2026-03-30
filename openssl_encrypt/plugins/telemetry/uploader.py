#!/usr/bin/env python3
"""
Telemetry Uploader - HTTPS batch uploader with retry logic.

PRIVACY CRITICAL:
- TLS certificate validation enforced (no self-signed certs)
- Retry with exponential backoff
- Rate limiting awareness
- Only uploads already-filtered telemetry data

This uploader provides:
1. Secure HTTPS uploads (TLS 1.2+)
2. Batch uploads (efficient)
3. Retry with backoff (resilient)
4. Rate limiting handling
"""

import time
from typing import Dict, List, Optional

import requests


class TelemetryUploader:
    """
    Sends buffered events to telemetry server via HTTPS.

    SECURITY:
    - TLS certificate validation enforced
    - Bearer token authentication
    - Batch uploads (max 1000 events per request)
    - Exponential backoff on failures
    """

    def __init__(self, config, key_manager):
        """
        Initialize TelemetryUploader.

        Args:
            config: Configuration object with server_url and batch settings
            key_manager: APIKeyManager instance for authentication
        """
        self.config = config
        self.key_manager = key_manager
        self.server_url = config.server_url
        self.batch_size = config.batch_size
        self.max_retries = 3
        self.timeout = 30  # seconds

    def upload_batch(self, events: List[Dict]) -> Optional[Dict]:
        """
        Uploads batch of telemetry events to server.

        Args:
            events: List of event dictionaries (already filtered)

        Returns:
            dict or None: Response data if successful, None on failure
                         Response format: {"received": N, "processed": N}
        """
        if not events:
            return {"received": 0, "processed": 0}

        # Limit batch size (server may enforce limits)
        if len(events) > 1000:
            events = events[:1000]

        # Get API key
        api_key = self.key_manager.get_api_key()
        if not api_key:
            # Failed to get API key (registration failed)
            return None

        # Prepare request
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        payload = {"events": events}

        # Try upload with retries
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    f"{self.server_url}/api/v1/telemetry/events",
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                    verify=True,  # CRITICAL: Enforce TLS certificate validation
                )

                # Handle response codes
                if response.status_code == 200:
                    # Success
                    return response.json()

                elif response.status_code == 401:
                    # Unauthorized - API key invalid or expired
                    # Try to refresh key
                    if self.key_manager.refresh_key():
                        # Retry with new key
                        api_key = self.key_manager.get_api_key()
                        headers["Authorization"] = f"Bearer {api_key}"
                        continue
                    else:
                        # Refresh failed
                        return None

                elif response.status_code == 429:
                    # Rate limited - wait and retry
                    retry_after = self._get_retry_after(response)
                    time.sleep(retry_after)
                    continue

                elif response.status_code >= 500:
                    # Server error - retry with backoff
                    backoff = self._calculate_backoff(attempt)
                    time.sleep(backoff)
                    continue

                else:
                    # Other error (400, etc.) - don't retry
                    return None

            except requests.RequestException:
                # Network error - retry with backoff
                if attempt < self.max_retries - 1:
                    backoff = self._calculate_backoff(attempt)
                    time.sleep(backoff)
                    continue
                else:
                    return None

        # All retries exhausted
        return None

    def _get_retry_after(self, response: requests.Response) -> int:
        """
        Extracts Retry-After header value.

        Args:
            response: HTTP response object

        Returns:
            int: Seconds to wait before retry (default: 60)
        """
        retry_after = response.headers.get("Retry-After")

        if retry_after:
            try:
                return int(retry_after)
            except ValueError:
                pass

        # Default: 60 seconds
        return 60

    def _calculate_backoff(self, attempt: int) -> float:
        """
        Calculates exponential backoff delay.

        Args:
            attempt: Current retry attempt (0-indexed)

        Returns:
            float: Seconds to wait before retry
        """
        # Exponential backoff: 2^attempt seconds
        # Attempt 0: 1 second
        # Attempt 1: 2 seconds
        # Attempt 2: 4 seconds
        base_delay = 2**attempt
        return min(base_delay, 60)  # Cap at 60 seconds

    def test_connection(self) -> bool:
        """
        Tests connection to telemetry server.

        Returns:
            bool: True if server is reachable, False otherwise
        """
        try:
            response = requests.get(f"{self.server_url}/health", timeout=10, verify=True)
            return response.status_code == 200
        except requests.RequestException:
            return False
