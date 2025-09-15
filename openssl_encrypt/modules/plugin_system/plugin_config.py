#!/usr/bin/env python3
"""
Plugin Configuration Manager for OpenSSL Encrypt

This module provides secure configuration management for plugins, ensuring
configuration data is validated, sanitized, and kept separate from sensitive
system configuration.

Security Features:
- Configuration isolation per plugin
- Input validation and sanitization
- No access to sensitive system configuration
- Schema validation for plugin configs
- Secure defaults and fallbacks
"""

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)


class ConfigValidationError(Exception):
    """Raised when plugin configuration validation fails."""

    pass


class PluginConfigSchema:
    """
    Schema definition for plugin configuration validation.
    Ensures plugin configs are safe and well-formed.
    """

    def __init__(self):
        self.fields: Dict[str, Dict[str, Any]] = {}
        self.required_fields: Set[str] = set()

    def add_field(
        self,
        name: str,
        field_type: type,
        required: bool = False,
        default: Any = None,
        validator: Optional[callable] = None,
        description: str = "",
    ) -> "PluginConfigSchema":
        """
        Add field to schema.

        Args:
            name: Field name
            field_type: Expected Python type
            required: Whether field is required
            default: Default value if not provided
            validator: Optional validation function
            description: Field description
        """
        self.fields[name] = {
            "type": field_type,
            "required": required,
            "default": default,
            "validator": validator,
            "description": description,
        }

        if required:
            self.required_fields.add(name)

        return self

    def validate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate configuration against schema.

        Args:
            config: Configuration to validate

        Returns:
            Validated and normalized configuration

        Raises:
            ConfigValidationError: If validation fails
        """
        validated = {}

        # Check required fields
        for field in self.required_fields:
            if field not in config:
                raise ConfigValidationError(f"Required field missing: {field}")

        # Validate each field
        for field_name, field_def in self.fields.items():
            if field_name in config:
                value = config[field_name]
                validated[field_name] = self._validate_field(field_name, value, field_def)
            elif field_def.get("default") is not None:
                validated[field_name] = field_def["default"]

        # Check for unknown fields
        unknown_fields = set(config.keys()) - set(self.fields.keys())
        if unknown_fields:
            logger.warning(f"Unknown configuration fields: {unknown_fields}")

        return validated

    def _validate_field(self, field_name: str, value: Any, field_def: Dict[str, Any]) -> Any:
        """Validate individual field."""
        expected_type = field_def["type"]

        # Type checking
        if not isinstance(value, expected_type):
            # Try type coercion for basic types
            if expected_type in (int, float, str, bool):
                try:
                    value = expected_type(value)
                except (ValueError, TypeError):
                    raise ConfigValidationError(
                        f"Field {field_name} must be {expected_type.__name__}, got {type(value).__name__}"
                    )
            else:
                raise ConfigValidationError(
                    f"Field {field_name} must be {expected_type.__name__}, got {type(value).__name__}"
                )

        # Custom validation
        validator = field_def.get("validator")
        if validator and not validator(value):
            raise ConfigValidationError(f"Field {field_name} failed validation")

        return value

    def get_field_info(self) -> Dict[str, Dict[str, Any]]:
        """Get schema information for documentation."""
        return self.fields.copy()


class PluginConfigManager:
    """
    Manages configuration for plugins with security and validation.

    Features:
    - Per-plugin configuration isolation
    - Schema validation
    - Secure storage (no sensitive data)
    - Configuration versioning and migration
    - Default value management
    """

    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = (
            Path(config_dir) if config_dir else Path.home() / ".openssl_encrypt" / "plugins"
        )
        self.configs: Dict[str, Dict[str, Any]] = {}
        self.schemas: Dict[str, PluginConfigSchema] = {}
        self.lock = threading.RLock()

        # Create config directory if it doesn't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Load existing configurations
        self._load_all_configs()

    def register_plugin_schema(self, plugin_id: str, schema: PluginConfigSchema) -> None:
        """
        Register configuration schema for plugin.

        Args:
            plugin_id: Plugin identifier
            schema: Configuration schema
        """
        with self.lock:
            self.schemas[plugin_id] = schema
            logger.info(f"Registered configuration schema for plugin: {plugin_id}")

    def set_plugin_config(self, plugin_id: str, config: Dict[str, Any]) -> None:
        """
        Set configuration for plugin.

        Args:
            plugin_id: Plugin identifier
            config: Configuration dictionary

        Raises:
            ConfigValidationError: If configuration is invalid
        """
        with self.lock:
            # Validate against schema if available
            if plugin_id in self.schemas:
                config = self.schemas[plugin_id].validate(config)
            else:
                # Basic security validation without schema
                config = self._basic_validate_config(config)

            # Store configuration
            self.configs[plugin_id] = config

            # Save to disk
            self._save_plugin_config(plugin_id, config)

            logger.info(f"Updated configuration for plugin: {plugin_id}")

    def get_plugin_config(self, plugin_id: str) -> Dict[str, Any]:
        """
        Get configuration for plugin.

        Args:
            plugin_id: Plugin identifier

        Returns:
            Plugin configuration dictionary
        """
        with self.lock:
            if plugin_id in self.configs:
                return self.configs[plugin_id].copy()

            # Try loading from disk
            loaded_config = self._load_plugin_config(plugin_id)
            if loaded_config:
                self.configs[plugin_id] = loaded_config
                return loaded_config.copy()

            # Return default configuration
            return self._get_default_config(plugin_id)

    def update_plugin_config(self, plugin_id: str, updates: Dict[str, Any]) -> None:
        """
        Update specific fields in plugin configuration.

        Args:
            plugin_id: Plugin identifier
            updates: Dictionary of field updates
        """
        with self.lock:
            current_config = self.get_plugin_config(plugin_id)
            current_config.update(updates)
            self.set_plugin_config(plugin_id, current_config)

    def delete_plugin_config(self, plugin_id: str) -> bool:
        """
        Delete plugin configuration.

        Args:
            plugin_id: Plugin identifier

        Returns:
            True if configuration was deleted
        """
        with self.lock:
            # Remove from memory
            if plugin_id in self.configs:
                del self.configs[plugin_id]

            # Remove from disk
            config_file = self._get_config_file_path(plugin_id)
            if config_file.exists():
                try:
                    config_file.unlink()
                    logger.info(f"Deleted configuration for plugin: {plugin_id}")
                    return True
                except Exception as e:
                    logger.error(f"Error deleting config file for {plugin_id}: {e}")
                    return False

            return True

    def list_plugin_configs(self) -> List[str]:
        """List all plugins with configuration."""
        with self.lock:
            # Combine in-memory and on-disk configs
            all_plugins = set(self.configs.keys())

            # Add plugins with config files
            for config_file in self.config_dir.glob("*.json"):
                plugin_id = config_file.stem
                all_plugins.add(plugin_id)

            return list(all_plugins)

    def get_plugin_config_info(self, plugin_id: str) -> Dict[str, Any]:
        """Get configuration information including schema details."""
        config = self.get_plugin_config(plugin_id)

        info = {
            "plugin_id": plugin_id,
            "config": config,
            "has_schema": plugin_id in self.schemas,
        }

        if plugin_id in self.schemas:
            info["schema"] = self.schemas[plugin_id].get_field_info()

        return info

    def validate_plugin_config(self, plugin_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate configuration without saving it.

        Args:
            plugin_id: Plugin identifier
            config: Configuration to validate

        Returns:
            Validated configuration

        Raises:
            ConfigValidationError: If validation fails
        """
        if plugin_id in self.schemas:
            return self.schemas[plugin_id].validate(config)
        else:
            return self._basic_validate_config(config)

    def _load_all_configs(self) -> None:
        """Load all plugin configurations from disk."""
        if not self.config_dir.exists():
            return

        for config_file in self.config_dir.glob("*.json"):
            plugin_id = config_file.stem
            try:
                config = self._load_plugin_config(plugin_id)
                if config:
                    self.configs[plugin_id] = config
            except Exception as e:
                logger.error(f"Error loading config for plugin {plugin_id}: {e}")

    def _load_plugin_config(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Load plugin configuration from disk."""
        config_file = self._get_config_file_path(plugin_id)

        if not config_file.exists():
            return None

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)

            # Basic validation
            if not isinstance(config, dict):
                logger.error(f"Invalid config format for plugin {plugin_id}: not a dictionary")
                return None

            return config

        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading config file for plugin {plugin_id}: {e}")
            return None

    def _save_plugin_config(self, plugin_id: str, config: Dict[str, Any]) -> None:
        """Save plugin configuration to disk."""
        config_file = self._get_config_file_path(plugin_id)

        try:
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, sort_keys=True)

            # Set restrictive permissions (Unix only)
            if hasattr(os, "chmod"):
                os.chmod(config_file, 0o600)  # Read/write for owner only

        except (IOError, json.JSONEncodeError) as e:
            logger.error(f"Error saving config file for plugin {plugin_id}: {e}")
            raise ConfigValidationError(f"Could not save configuration: {e}")

    def _get_config_file_path(self, plugin_id: str) -> Path:
        """Get path to plugin configuration file."""
        # Sanitize plugin ID for filename
        safe_plugin_id = "".join(c for c in plugin_id if c.isalnum() or c in "_-.")
        return self.config_dir / f"{safe_plugin_id}.json"

    def _get_default_config(self, plugin_id: str) -> Dict[str, Any]:
        """Get default configuration for plugin."""
        default_config = {"enabled": True}

        # Add schema defaults if available
        if plugin_id in self.schemas:
            schema = self.schemas[plugin_id]
            for field_name, field_def in schema.fields.items():
                if field_def.get("default") is not None:
                    default_config[field_name] = field_def["default"]

        return default_config

    def _basic_validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Basic validation for configs without schema."""
        if not isinstance(config, dict):
            raise ConfigValidationError("Configuration must be a dictionary")

        # Check for sensitive data patterns
        sensitive_patterns = [
            "password",
            "secret",
            "key",
            "token",
            "auth",
            "credential",
            "private",
            "passphrase",
            "api_key",
            "access_token",
        ]

        for key, value in config.items():
            # Check key names
            key_lower = key.lower()
            if any(pattern in key_lower for pattern in sensitive_patterns):
                logger.warning(f"Configuration key '{key}' appears to contain sensitive data")

            # Check string values
            if isinstance(value, str) and len(value) > 100:
                # Long strings might contain sensitive data
                value_lower = value.lower()
                if any(
                    pattern in value_lower for pattern in sensitive_patterns[:6]
                ):  # Check fewer patterns for values
                    logger.warning(f"Configuration value for '{key}' might contain sensitive data")

            # Validate value types (only allow safe types)
            if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                raise ConfigValidationError(
                    f"Invalid value type for '{key}': {type(value).__name__}"
                )

        return config.copy()


# Common schema builder helpers
def create_string_field(
    required: bool = False, default: str = "", max_length: int = 1000
) -> Dict[str, Any]:
    """Create string field definition."""
    return {
        "type": str,
        "required": required,
        "default": default,
        "validator": lambda x: len(x) <= max_length,
    }


def create_integer_field(
    required: bool = False, default: int = 0, min_val: int = None, max_val: int = None
) -> Dict[str, Any]:
    """Create integer field definition."""

    def validator(x):
        if min_val is not None and x < min_val:
            return False
        if max_val is not None and x > max_val:
            return False
        return True

    return {"type": int, "required": required, "default": default, "validator": validator}


def create_boolean_field(required: bool = False, default: bool = False) -> Dict[str, Any]:
    """Create boolean field definition."""
    return {"type": bool, "required": required, "default": default, "validator": None}


def create_choice_field(
    choices: List[Any], required: bool = False, default: Any = None
) -> Dict[str, Any]:
    """Create choice field definition."""
    return {
        "type": type(choices[0]) if choices else str,
        "required": required,
        "default": default,
        "validator": lambda x: x in choices,
    }
