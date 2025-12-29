#!/usr/bin/env python3
"""
Steganography Plugin for OpenSSL Encrypt

This plugin provides steganography capabilities for hiding encrypted data
within various media formats (images and audio files).
"""

import logging
from typing import Any, Dict, Optional, Set

from ...modules.plugin_system.plugin_base import (
    BasePlugin,
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
    PluginType,
)
from .core import CapacityError, CoverMediaError, SteganographyError
from .transport import SteganographyTransport

logger = logging.getLogger(__name__)


class SteganographyPlugin(BasePlugin):
    """
    Steganography plugin for hiding data in media files.

    This plugin provides utility functions for:
    - Hiding encrypted data in cover media (images, audio)
    - Extracting hidden data from stego media
    - Analyzing capacity and security of cover media
    - Getting format-specific information

    Security:
    - Only works with encrypted data (never plaintext)
    - No access to encryption keys or passwords
    - Sandboxed execution with whitelisted PIL/numpy imports
    """

    def __init__(self):
        super().__init__(plugin_id="steganography", name="Steganography", version="1.0.0")
        self._transport = None

    def get_plugin_type(self) -> PluginType:
        """This is a utility plugin providing multiple functions."""
        return PluginType.UTILITY

    def get_required_capabilities(self) -> Set[PluginCapability]:
        """
        Required capabilities for steganography operations.

        Returns:
            Set of required capabilities:
            - READ_FILES: To read cover media and stego files
            - WRITE_LOGS: For logging operations
            - ACCESS_CONFIG: For plugin configuration
        """
        return {
            PluginCapability.READ_FILES,
            PluginCapability.WRITE_LOGS,
            PluginCapability.ACCESS_CONFIG,
        }

    def get_description(self) -> str:
        """Return human-readable description."""
        return (
            "Steganography plugin for hiding encrypted data in media files. "
            "Supports multiple image formats (PNG, JPEG, TIFF, WEBP) and "
            "audio formats (WAV, FLAC, MP3) with error correction and "
            "security analysis capabilities."
        )

    def get_utility_functions(self) -> Dict[str, callable]:
        """
        Return available utility functions.

        Returns:
            Dict mapping function names to callable functions:
            - hide: Embed data into cover media
            - extract: Extract hidden data from stego media
            - analyze: Analyze capacity and security of cover media
            - get_capacity: Get embedding capacity for a media file
            - is_available: Check if steganography dependencies are available
        """
        return {
            "hide": self.hide_data,
            "extract": self.extract_data,
            "analyze": self.analyze_media,
            "get_capacity": self.get_capacity,
            "is_available": self.is_available,
        }

    def initialize(self, config: Dict[str, Any]) -> PluginResult:
        """
        Initialize plugin with configuration.

        Args:
            config: Plugin configuration dictionary

        Returns:
            PluginResult indicating initialization success/failure
        """
        try:
            # Lazy-load transport (will be implemented in Phase 4)
            self.logger.info("Steganography plugin initialized")
            return PluginResult.success_result("Steganography plugin initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize steganography plugin: {e}")
            return PluginResult.error_result(f"Initialization failed: {e}")

    def execute(self, context: PluginSecurityContext) -> PluginResult:
        """
        Execute utility function based on context.

        Args:
            context: Security context with function_name in metadata

        Returns:
            PluginResult from the executed function
        """
        function_name = context.metadata.get("function_name")
        if not function_name:
            return PluginResult.error_result("No utility function specified")

        functions = self.get_utility_functions()
        if function_name not in functions:
            return PluginResult.error_result(f"Unknown utility function: {function_name}")

        try:
            function = functions[function_name]
            # Extract kwargs from context metadata
            kwargs = context.metadata.get("kwargs", {})
            result = function(**kwargs)
            return result
        except Exception as e:
            self.logger.error(f"Error executing {function_name}: {e}")
            return PluginResult.error_result(f"Execution failed: {e}")

    def hide_data(
        self,
        cover_path: str,
        data: bytes,
        output_path: str,
        method: str = "lsb",
        bits_per_channel: int = 1,
        password: Optional[str] = None,
        **options,
    ) -> PluginResult:
        """
        Embed encrypted data into cover media.

        Args:
            cover_path: Path to cover media file
            data: Encrypted data to hide
            output_path: Path for output stego file
            method: Steganography method (lsb, dct, etc.)
            bits_per_channel: Bits per channel for LSB (1-8)
            password: Optional password for additional protection
            **options: Additional format-specific options

        Returns:
            PluginResult with success status and metadata
        """
        try:
            self.logger.info(f"Hiding {len(data)} bytes in {cover_path}")

            # Create transport with specified options
            transport = SteganographyTransport(
                method=method, bits_per_channel=bits_per_channel, password=password, **options
            )

            # Hide data in media
            transport.hide_data_in_media(data, cover_path, output_path)

            return PluginResult.success_result(
                f"Successfully hid {len(data)} bytes in {cover_path}",
                {
                    "cover_path": cover_path,
                    "output_path": output_path,
                    "data_size": len(data),
                    "method": method,
                },
            )
        except (CapacityError, CoverMediaError, SteganographyError) as e:
            self.logger.error(f"Failed to hide data: {e}")
            return PluginResult.error_result(f"Hide operation failed: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error hiding data: {e}")
            return PluginResult.error_result(f"Hide operation failed: {e}")

    def extract_data(
        self,
        stego_path: str,
        method: str = "lsb",
        bits_per_channel: int = 1,
        password: Optional[str] = None,
        **options,
    ) -> PluginResult:
        """
        Extract hidden data from stego media.

        Args:
            stego_path: Path to stego media file
            method: Steganography method used (lsb, dct, etc.)
            bits_per_channel: Bits per channel for LSB (1-8)
            password: Optional password if data was protected
            **options: Additional format-specific options

        Returns:
            PluginResult with extracted data in result.data["extracted_data"]
        """
        try:
            self.logger.info(f"Extracting data from {stego_path}")

            # Create transport with specified options
            transport = SteganographyTransport(
                method=method, bits_per_channel=bits_per_channel, password=password, **options
            )

            # Extract data from media
            extracted_data = transport.extract_data_from_media(stego_path)

            return PluginResult.success_result(
                f"Successfully extracted {len(extracted_data)} bytes from {stego_path}",
                {
                    "stego_path": stego_path,
                    "method": method,
                    "data_size": len(extracted_data),
                    "extracted_data": extracted_data,
                },
            )
        except (CoverMediaError, SteganographyError) as e:
            self.logger.error(f"Failed to extract data: {e}")
            return PluginResult.error_result(f"Extract operation failed: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error extracting data: {e}")
            return PluginResult.error_result(f"Extract operation failed: {e}")

    def analyze_media(self, media_path: str, method: str = "lsb", **options) -> PluginResult:
        """
        Analyze capacity and security of cover media.

        Args:
            media_path: Path to media file to analyze
            method: Steganography method to analyze for
            **options: Additional analysis options

        Returns:
            PluginResult with analysis data including capacity and security metrics
        """
        try:
            self.logger.info(f"Analyzing {media_path}")

            # Create transport with specified options
            bits_per_channel = options.get("bits_per_channel", 1)
            password = options.get("password", None)

            transport = SteganographyTransport(
                method=method, bits_per_channel=bits_per_channel, password=password, **options
            )

            # Get capacity
            capacity = transport.get_capacity(media_path)

            # Basic analysis result
            # TODO: Add more detailed security analysis using core.analysis module
            return PluginResult.success_result(
                f"Analyzed {media_path}: capacity {capacity} bytes",
                {
                    "media_path": media_path,
                    "method": method,
                    "capacity_bytes": capacity,
                    "bits_per_channel": bits_per_channel,
                },
            )
        except (CoverMediaError, SteganographyError) as e:
            self.logger.error(f"Failed to analyze media: {e}")
            return PluginResult.error_result(f"Analysis failed: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error analyzing media: {e}")
            return PluginResult.error_result(f"Analysis failed: {e}")

    def get_capacity(self, media_path: str, method: str = "lsb", **options) -> PluginResult:
        """
        Get embedding capacity for a media file.

        Args:
            media_path: Path to media file
            method: Steganography method
            **options: Method-specific options

        Returns:
            PluginResult with capacity in bytes
        """
        try:
            self.logger.info(f"Calculating capacity for {media_path}")

            # Create transport with specified options
            bits_per_channel = options.get("bits_per_channel", 1)
            password = options.get("password", None)

            transport = SteganographyTransport(
                method=method, bits_per_channel=bits_per_channel, password=password, **options
            )

            # Get capacity
            capacity = transport.get_capacity(media_path)

            return PluginResult.success_result(
                f"Capacity: {capacity} bytes",
                {
                    "media_path": media_path,
                    "method": method,
                    "capacity_bytes": capacity,
                },
            )
        except (CoverMediaError, SteganographyError) as e:
            self.logger.error(f"Failed to calculate capacity: {e}")
            return PluginResult.error_result(f"Capacity calculation failed: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error calculating capacity: {e}")
            return PluginResult.error_result(f"Capacity calculation failed: {e}")

    def is_available(self) -> PluginResult:
        """
        Check if steganography dependencies are available.

        Returns:
            PluginResult with availability status and missing dependencies
        """
        try:
            missing_deps = []

            try:
                import PIL
            except ImportError:
                missing_deps.append("PIL/Pillow")

            try:
                import numpy
            except ImportError:
                missing_deps.append("numpy")

            if missing_deps:
                return PluginResult.error_result(
                    f"Missing dependencies: {', '.join(missing_deps)}",
                    {"missing": missing_deps, "available": False},
                )

            return PluginResult.success_result(
                "All dependencies available", {"available": True, "missing": []}
            )
        except Exception as e:
            return PluginResult.error_result(f"Availability check failed: {e}")


# Plugin instance for auto-registration
plugin_instance = SteganographyPlugin()
