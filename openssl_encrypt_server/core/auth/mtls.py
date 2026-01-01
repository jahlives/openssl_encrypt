#!/usr/bin/env python3
"""
Direct mTLS Authentication.

This module handles authentication when the server directly terminates the TLS
connection and extracts the client certificate from the SSL context.

SECURITY:
- Extracts peer certificate from SSL transport layer
- Computes SHA-256 fingerprint for client identification
- Parses certificate Subject DN for additional metadata
- Validates certificate format and availability
"""

import logging
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)


class MTLSAuth:
    """
    Direct mTLS authentication - extracts certificate from SSL context.

    When the server directly terminates TLS (with `ssl_cert_reqs=CERT_REQUIRED`),
    this handler extracts the client certificate from the request's transport layer
    and computes the fingerprint for authentication.

    Security Model:
    - Client certificate must be present (enforced by ssl_cert_reqs)
    - Certificate is extracted from SSL object
    - SHA-256 fingerprint computed for identification
    - Subject DN extracted for metadata
    """

    async def get_client_fingerprint(self, request: Request) -> str:
        """
        Extract client certificate fingerprint from SSL connection.

        Args:
            request: FastAPI Request object

        Returns:
            Normalized certificate fingerprint (SHA-256, 64 hex chars)

        Raises:
            HTTPException: 401 if certificate not available or invalid
        """
        # Get transport from request scope
        transport = request.scope.get("transport")
        if not transport:
            logger.error("No transport in request scope")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TLS transport not available"
            )

        # Get SSL object from transport
        try:
            ssl_object = transport.get_extra_info("ssl_object")
            if not ssl_object:
                logger.error("No SSL object in transport")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="SSL connection not established"
                )
        except Exception as e:
            logger.error(f"Failed to get SSL object: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to access SSL connection info"
            )

        # Get peer certificate (binary DER format)
        try:
            cert_der = ssl_object.getpeercert(binary_form=True)
            if not cert_der:
                logger.error("No peer certificate available")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Client certificate not provided"
                )
        except Exception as e:
            logger.error(f"Failed to get peer certificate: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to retrieve client certificate"
            )

        # Parse certificate with cryptography library
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
        except Exception as e:
            logger.error(f"Failed to parse certificate: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid certificate format"
            )

        # Compute SHA-256 fingerprint
        try:
            fingerprint_bytes = cert.fingerprint(hashes.SHA256())
            fingerprint = fingerprint_bytes.hex()  # Already lowercase, no colons
            logger.debug(f"Authenticated via mTLS: {fingerprint[:16]}...")
            return fingerprint
        except Exception as e:
            logger.error(f"Failed to compute fingerprint: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to compute certificate fingerprint"
            )

    async def get_client_dn(self, request: Request) -> Optional[str]:
        """
        Extract client certificate Distinguished Name (DN) from SSL connection.

        Args:
            request: FastAPI Request object

        Returns:
            Certificate subject DN in RFC4514 format, or None on error
        """
        # Get transport from request scope
        transport = request.scope.get("transport")
        if not transport:
            return None

        # Get SSL object
        try:
            ssl_object = transport.get_extra_info("ssl_object")
            if not ssl_object:
                return None
        except Exception:
            return None

        # Get peer certificate
        try:
            cert_der = ssl_object.getpeercert(binary_form=True)
            if not cert_der:
                return None
        except Exception:
            return None

        # Parse certificate and extract subject DN
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            dn = cert.subject.rfc4514_string()
            logger.debug(f"Client DN: {dn}")
            return dn
        except Exception as e:
            logger.warning(f"Failed to extract DN: {e}")
            return None
