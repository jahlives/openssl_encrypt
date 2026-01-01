#!/usr/bin/env python3
"""
Proxy-based mTLS Authentication.

This module handles authentication when a reverse proxy (like Nginx) terminates
mTLS and forwards certificate information via HTTP headers.

SECURITY:
- Only accepts headers from trusted proxy IP addresses/networks
- Validates certificate verification status (X-Client-Cert-Verify: SUCCESS)
- Normalizes fingerprints to prevent bypass attempts
- Returns appropriate HTTP status codes for auth failures
"""

import ipaddress
import logging
from typing import List, Optional

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)


class ProxyAuth:
    """
    Authentication via reverse proxy headers.

    The proxy terminates mTLS and passes client certificate information via
    HTTP headers. This handler validates the proxy IP and extracts the cert
    fingerprint for client identification.

    Security Model:
    - Requests must originate from trusted proxy IPs
    - X-Client-Cert-Verify header must be "SUCCESS" (if verify_header enabled)
    - X-Client-Cert-Fingerprint header must be present and non-empty
    - Fingerprints are normalized (lowercase, no colons)
    """

    def __init__(
        self,
        fingerprint_header: str = "X-Client-Cert-Fingerprint",
        trusted_proxies: Optional[List[str]] = None,
        dn_header: Optional[str] = None,
        verify_header: Optional[str] = None,
    ):
        """
        Initialize ProxyAuth.

        Args:
            fingerprint_header: Header name for certificate SHA-256 fingerprint
            trusted_proxies: List of trusted proxy IPs/networks (CIDR notation)
            dn_header: Optional header for certificate DN
            verify_header: Optional header for verification status check
        """
        self.fingerprint_header = fingerprint_header
        self.dn_header = dn_header
        self.verify_header = verify_header

        # Parse trusted proxy networks
        self.trusted_networks = []
        if trusted_proxies:
            for proxy in trusted_proxies:
                try:
                    # Support both individual IPs and CIDR notation
                    self.trusted_networks.append(ipaddress.ip_network(proxy, strict=False))
                except ValueError as e:
                    logger.error(f"Invalid proxy address: {proxy} - {e}")
                    raise ValueError(f"Invalid trusted proxy address: {proxy}")
        else:
            # Default: trust localhost and private networks
            self.trusted_networks = [
                ipaddress.ip_network("127.0.0.0/8"),
                ipaddress.ip_network("::1/128"),
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            ]

        logger.info(f"ProxyAuth initialized with {len(self.trusted_networks)} trusted networks")

    def _is_trusted_proxy(self, client_ip: str) -> bool:
        """
        Check if request originates from a trusted proxy.

        Args:
            client_ip: Client IP address from request

        Returns:
            True if IP is in trusted networks
        """
        try:
            ip_addr = ipaddress.ip_address(client_ip)
            for network in self.trusted_networks:
                if ip_addr in network:
                    return True
            return False
        except ValueError:
            logger.warning(f"Invalid IP address: {client_ip}")
            return False

    def _normalize_fingerprint(self, fingerprint: str) -> str:
        """
        Normalize certificate fingerprint.

        Ensures consistent format:
        - Lowercase
        - No colons or separators
        - Only hex characters

        Args:
            fingerprint: Raw fingerprint from header

        Returns:
            Normalized fingerprint

        Raises:
            ValueError: If fingerprint format is invalid
        """
        # Remove common separators
        normalized = fingerprint.replace(":", "").replace(" ", "").replace("-", "").lower()

        # Validate hex string
        if not all(c in "0123456789abcdef" for c in normalized):
            raise ValueError("Fingerprint contains invalid characters")

        # SHA-256 fingerprint should be 64 hex characters
        if len(normalized) != 64:
            raise ValueError(f"Invalid fingerprint length: {len(normalized)} (expected 64)")

        return normalized

    async def get_client_fingerprint(self, request: Request) -> str:
        """
        Extract and validate client certificate fingerprint from proxy headers.

        Args:
            request: FastAPI Request object

        Returns:
            Normalized certificate fingerprint (SHA-256, 64 hex chars)

        Raises:
            HTTPException: 403 if not from trusted proxy, 401 if fingerprint missing/invalid
        """
        # Get client IP
        client_ip = request.client.host if request.client else None
        if not client_ip:
            logger.error("No client IP in request")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Client IP not available"
            )

        # Validate trusted proxy
        if not self._is_trusted_proxy(client_ip):
            logger.warning(f"Untrusted proxy IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Request not from trusted proxy"
            )

        # Check certificate verification status (if enabled)
        if self.verify_header:
            verify_status = request.headers.get(self.verify_header)
            if verify_status != "SUCCESS":
                logger.warning(f"Certificate verification failed: {verify_status}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Client certificate verification failed"
                )

        # Extract fingerprint
        fingerprint = request.headers.get(self.fingerprint_header)
        if not fingerprint:
            logger.warning(f"Missing header: {self.fingerprint_header}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client certificate fingerprint not provided"
            )

        # Normalize and validate fingerprint
        try:
            normalized = self._normalize_fingerprint(fingerprint)
            logger.debug(f"Authenticated via proxy: {normalized[:16]}...")
            return normalized
        except ValueError as e:
            logger.error(f"Invalid fingerprint format: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid certificate fingerprint: {e}"
            )

    async def get_client_dn(self, request: Request) -> Optional[str]:
        """
        Extract client certificate Distinguished Name (DN) from proxy headers.

        Args:
            request: FastAPI Request object

        Returns:
            Certificate DN if available, None otherwise
        """
        if not self.dn_header:
            return None

        dn = request.headers.get(self.dn_header)
        if dn:
            logger.debug(f"Client DN: {dn}")
        return dn
