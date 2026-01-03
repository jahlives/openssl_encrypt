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

import hashlib
import ipaddress
import logging
import urllib.parse
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, Request, status

from ..security_logger import (
    SecurityEventSeverity,
    SecurityEventType,
    get_security_logger,
)

logger = logging.getLogger(__name__)
security_logger = get_security_logger()


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
        cert_header: str = "X-Client-Cert",
        trusted_proxies: Optional[List[str]] = None,
        dn_header: Optional[str] = None,
        verify_header: Optional[str] = None,
    ):
        """
        Initialize ProxyAuth.

        Args:
            fingerprint_header: Header name for certificate SHA-256 fingerprint
            cert_header: Header name for raw certificate (PEM, URL-encoded)
            trusted_proxies: List of trusted proxy IPs/networks (CIDR notation)
            dn_header: Optional header for certificate DN
            verify_header: Optional header for verification status check
        """
        self.fingerprint_header = fingerprint_header
        self.cert_header = cert_header
        self.dn_header = dn_header
        self.verify_header = verify_header

        # Parse trusted proxy networks
        self.trusted_networks = []
        if trusted_proxies:
            for proxy in trusted_proxies:
                try:
                    # Support both individual IPs and CIDR notation
                    network = ipaddress.ip_network(proxy, strict=False)

                    # SECURITY: Reject networks larger than /24 to prevent broad trust
                    # Exception: Allow localhost ranges (127.0.0.0/8, ::1/128)
                    if network.prefixlen < 24:
                        # Allow localhost ranges
                        localhost_v4 = ipaddress.ip_network("127.0.0.0/8")
                        localhost_v6 = ipaddress.ip_network("::1/128")

                        if network != localhost_v4 and network != localhost_v6:
                            logger.error(
                                f"Rejected overly broad proxy network: {proxy} "
                                f"(prefix length {network.prefixlen} < 24). "
                                f"Please specify exact IPs or smaller subnets."
                            )
                            raise ValueError(
                                f"Proxy network {proxy} is too broad (must be /24 or smaller). "
                                f"Specify exact IPs or use smaller CIDR ranges for security."
                            )

                    self.trusted_networks.append(network)
                    logger.info(f"Added trusted proxy network: {proxy}")
                except ValueError as e:
                    logger.error(f"Invalid proxy address: {proxy} - {e}")
                    raise ValueError(f"Invalid trusted proxy address: {proxy}")
        else:
            # No proxies configured - use minimal defaults (localhost only)
            logger.warning(
                "No trusted_proxies configured! Using localhost-only defaults. "
                "If using a reverse proxy, you MUST configure trusted_proxies explicitly "
                "in the configuration file to include your proxy's IP address."
            )
            self.trusted_networks = [
                ipaddress.ip_network("127.0.0.1/32"),  # IPv4 localhost only
                ipaddress.ip_network("::1/128"),        # IPv6 localhost only
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

    def _compute_fingerprint_from_cert(self, cert_pem: str) -> str:
        """
        Compute SHA-256 fingerprint from PEM-encoded certificate.

        Args:
            cert_pem: PEM-encoded certificate (may be URL-encoded)

        Returns:
            SHA-256 fingerprint as lowercase hex string (64 chars)

        Raises:
            ValueError: If certificate cannot be parsed
        """
        try:
            # URL-decode if needed (Nginx uses $ssl_client_escaped_cert)
            cert_data = urllib.parse.unquote(cert_pem)

            # Parse PEM certificate
            cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())

            # Compute SHA-256 of DER-encoded certificate
            cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
            fingerprint = hashlib.sha256(cert_der).hexdigest().lower()

            logger.debug(f"Computed fingerprint from certificate: {fingerprint[:16]}...")
            return fingerprint

        except Exception as e:
            logger.error(f"Failed to parse certificate: {e}")
            raise ValueError(f"Invalid certificate format: {e}")

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

        This method supports two modes:
        1. Raw certificate (X-Client-Cert): Computes SHA-256 from PEM certificate
        2. Pre-computed fingerprint (X-Client-Cert-Fingerprint): Uses provided hash

        Mode 1 is preferred as it allows Nginx to send SHA-1 while we compute SHA-256.

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

            # Log security event for untrusted proxy attempt
            security_logger.log_event(
                SecurityEventType.UNTRUSTED_PROXY,
                SecurityEventSeverity.WARNING,
                client_ip,
                {"client_ip": client_ip, "headers": dict(request.headers)},
                f"Request from untrusted proxy: {client_ip}"
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Request not from trusted proxy"
            )

        # Check certificate verification status (if enabled)
        if self.verify_header:
            verify_status = request.headers.get(self.verify_header)
            if verify_status != "SUCCESS":
                logger.warning(f"Certificate verification failed: {verify_status}")

                # Log security event for cert verification failure
                security_logger.log_event(
                    SecurityEventType.CERT_VERIFICATION_FAILED,
                    SecurityEventSeverity.WARNING,
                    client_ip,
                    {"verify_status": verify_status, "client_ip": client_ip},
                    f"Certificate verification failed: {verify_status}"
                )

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Client certificate verification failed"
                )

        # Try to get raw certificate first (preferred method)
        cert_pem = request.headers.get(self.cert_header)
        if cert_pem:
            try:
                fingerprint = self._compute_fingerprint_from_cert(cert_pem)
                logger.debug(f"Authenticated via proxy (raw cert): {fingerprint[:16]}...")
                return fingerprint
            except ValueError as e:
                logger.error(f"Failed to compute fingerprint from certificate: {e}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid client certificate: {e}"
                )

        # Fall back to pre-computed fingerprint header
        fingerprint = request.headers.get(self.fingerprint_header)
        if not fingerprint:
            logger.warning(f"Missing headers: {self.cert_header} and {self.fingerprint_header}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client certificate or fingerprint not provided"
            )

        # Normalize and validate fingerprint
        try:
            normalized = self._normalize_fingerprint(fingerprint)
            logger.debug(f"Authenticated via proxy (fingerprint): {normalized[:16]}...")
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

        Tries two methods:
        1. Extract from raw certificate (X-Client-Cert)
        2. Read from DN header (X-Client-Cert-DN)

        Args:
            request: FastAPI Request object

        Returns:
            Certificate DN if available, None otherwise
        """
        # Try to extract DN from raw certificate first
        cert_pem = request.headers.get(self.cert_header)
        if cert_pem:
            try:
                cert_data = urllib.parse.unquote(cert_pem)
                cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
                # Format DN as string (e.g., "CN=example.com,O=Example,C=US")
                dn = cert.subject.rfc4514_string()
                logger.debug(f"Client DN (from cert): {dn}")
                return dn
            except Exception as e:
                logger.warning(f"Could not extract DN from certificate: {e}")

        # Fall back to DN header
        if self.dn_header:
            dn = request.headers.get(self.dn_header)
            if dn:
                logger.debug(f"Client DN (from header): {dn}")
                return dn

        return None
