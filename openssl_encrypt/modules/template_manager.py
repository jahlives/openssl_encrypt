#!/usr/bin/env python3
"""
Enhanced Template Management System for OpenSSL Encrypt

This module provides an advanced template management system that integrates with
the configuration wizard, security analyzer, and CLI aliases to provide a
comprehensive template experience. It supports template creation, validation,
analysis, and management operations.

Design Philosophy:
- Template validation with security analysis integration
- Template generation from wizard configurations
- Template comparison and recommendation system
- Template metadata with creation context and security scores
- Backward compatibility with existing template system
"""

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from .config_analyzer import ConfigurationAnalyzer, analyze_configuration_from_args
from .security_scorer import SecurityLevel


class TemplateCategory(Enum):
    """Template categories for organization."""

    BUILT_IN = "built_in"
    USER_CREATED = "user_created"
    WIZARD_GENERATED = "wizard_generated"
    IMPORTED = "imported"
    RECOMMENDED = "recommended"


class TemplateFormat(Enum):
    """Supported template file formats."""

    JSON = "json"
    YAML = "yaml"


@dataclass
class TemplateMetadata:
    """Metadata for template files."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    category: TemplateCategory = TemplateCategory.USER_CREATED
    author: str = ""
    version: str = "1.0"
    created_date: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    modified_date: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    use_cases: List[str] = field(default_factory=list)
    security_score: float = 0.0
    security_level: str = ""
    tags: List[str] = field(default_factory=list)
    source: str = "manual"  # manual, wizard, analyzer, import
    compatibility: Dict[str, bool] = field(default_factory=dict)


@dataclass
class EnhancedTemplate:
    """Enhanced template with metadata and analysis."""

    metadata: TemplateMetadata
    config: Dict[str, Any]
    file_path: Optional[str] = None
    is_built_in: bool = False


class TemplateManager:
    """
    Enhanced template management system.

    Provides comprehensive template operations including creation, validation,
    analysis, comparison, and management with integration to other system
    components.
    """

    # Built-in template definitions with enhanced metadata
    BUILT_IN_TEMPLATES = {
        "quick": {
            "metadata": {
                "name": "Quick",
                "description": "Fast encryption with adequate security for everyday use",
                "category": TemplateCategory.BUILT_IN,
                "author": "OpenSSL Encrypt",
                "use_cases": ["personal", "development", "testing"],
                "tags": ["fast", "lightweight", "basic_security"],
                "source": "built_in",
            },
            "config": {
                "hash_config": {
                    "sha256": 1000,
                    "sha3_512": 10000,
                    "pbkdf2_iterations": 10000,
                    "scrypt": {"enabled": False},
                    "argon2": {"enabled": False},
                    "algorithm": "fernet",
                }
            },
        },
        "standard": {
            "metadata": {
                "name": "Standard",
                "description": "Balanced security and performance for important files",
                "category": TemplateCategory.BUILT_IN,
                "author": "OpenSSL Encrypt",
                "use_cases": ["business", "personal", "general"],
                "tags": ["balanced", "recommended", "moderate_security"],
                "source": "built_in",
            },
            "config": {
                "hash_config": {
                    "sha512": 10000,
                    "sha3_256": 10000,
                    "blake2b": 200000,
                    "blake3": 150000,
                    "shake256": 200000,
                    "scrypt": {"enabled": True, "n": 128, "r": 8, "p": 1},
                    "argon2": {
                        "enabled": True,
                        "time_cost": 3,
                        "memory_cost": 1048576,
                        "parallelism": 4,
                    },
                    "pbkdf2_iterations": 200000,
                    "algorithm": "aes-gcm-siv",
                }
            },
        },
        "paranoid": {
            "metadata": {
                "name": "Paranoid",
                "description": "Maximum security for highly sensitive data",
                "category": TemplateCategory.BUILT_IN,
                "author": "OpenSSL Encrypt",
                "use_cases": ["compliance", "archival", "high_security"],
                "tags": ["maximum_security", "high_performance_cost", "comprehensive"],
                "source": "built_in",
            },
            "config": {
                "hash_config": {
                    "sha512": 10000,
                    "sha256": 10000,
                    "sha3_256": 10000,
                    "sha3_512": 800000,
                    "blake2b": 800000,
                    "blake3": 150000,
                    "shake256": 400000,
                    "scrypt": {"enabled": True, "n": 256, "r": 16, "p": 2},
                    "argon2": {
                        "enabled": True,
                        "time_cost": 4,
                        "memory_cost": 2097152,
                        "parallelism": 8,
                    },
                    "balloon": {"enabled": True, "time_cost": 3, "space_cost": 65536},
                    "pbkdf2_iterations": 0,
                    "algorithm": "xchacha20-poly1305",
                }
            },
        },
    }

    def __init__(self, template_dir: Optional[str] = None):
        """Initialize template manager."""
        self.analyzer = ConfigurationAnalyzer()

        if template_dir is None:
            # Default to templates directory in project root
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            self.template_dir = os.path.join(project_root, "templates")
        else:
            self.template_dir = template_dir

        # Ensure template directory exists
        os.makedirs(self.template_dir, exist_ok=True)

        # Initialize built-in templates with analysis
        self._initialize_built_in_templates()

    def _initialize_built_in_templates(self):
        """Initialize built-in templates with security analysis."""
        for template_name, template_data in self.BUILT_IN_TEMPLATES.items():
            # Perform security analysis on built-in templates
            config = template_data["config"]["hash_config"]
            try:
                analysis = self.analyzer.analyze_configuration(config)
                template_data["metadata"]["security_score"] = analysis.overall_score
                template_data["metadata"]["security_level"] = analysis.security_level.name
                template_data["metadata"]["compatibility"] = {
                    "score": analysis.compatibility_matrix["overall_compatibility_score"],
                    "platforms": analysis.compatibility_matrix["platform_compatibility"],
                    "libraries": analysis.compatibility_matrix["library_compatibility"],
                }
            except Exception:
                # Fallback for analysis errors
                template_data["metadata"]["security_score"] = 5.0
                template_data["metadata"]["security_level"] = "MODERATE"

    def create_template_from_wizard(
        self,
        wizard_config: Dict[str, Any],
        name: str,
        description: str = "",
        use_cases: List[str] = None,
    ) -> EnhancedTemplate:
        """Create a template from wizard configuration."""
        metadata = TemplateMetadata(
            name=name,
            description=description or f"Template generated from configuration wizard",
            category=TemplateCategory.WIZARD_GENERATED,
            author="Configuration Wizard",
            use_cases=use_cases or [],
            source="wizard",
            tags=["wizard_generated", "custom"],
        )

        # Analyze the configuration
        try:
            analysis = self.analyzer.analyze_configuration(wizard_config)
            metadata.security_score = analysis.overall_score
            metadata.security_level = analysis.security_level.name

            # Add use case tags based on analysis
            if analysis.overall_score >= 8.0:
                metadata.tags.append("high_security")
            elif analysis.overall_score >= 6.0:
                metadata.tags.append("good_security")
            else:
                metadata.tags.append("basic_security")
        except Exception:
            metadata.security_score = 5.0
            metadata.security_level = "MODERATE"

        template = EnhancedTemplate(
            metadata=metadata, config={"hash_config": wizard_config}, is_built_in=False
        )

        return template

    def create_template_from_args(
        self, args, name: str, description: str = "", use_cases: List[str] = None
    ) -> EnhancedTemplate:
        """Create a template from parsed CLI arguments."""
        config = vars(args)

        metadata = TemplateMetadata(
            name=name,
            description=description or f"Template created from CLI configuration",
            category=TemplateCategory.USER_CREATED,
            author="CLI Configuration",
            use_cases=use_cases or [],
            source="cli",
            tags=["user_created", "cli_generated"],
        )

        # Analyze the configuration
        try:
            analysis = analyze_configuration_from_args(args)
            metadata.security_score = analysis.overall_score
            metadata.security_level = analysis.security_level.name
        except Exception:
            metadata.security_score = 5.0
            metadata.security_level = "MODERATE"

        template = EnhancedTemplate(
            metadata=metadata, config={"hash_config": config}, is_built_in=False
        )

        return template

    def save_template(
        self,
        template: EnhancedTemplate,
        filename: Optional[str] = None,
        format: TemplateFormat = TemplateFormat.JSON,
        overwrite: bool = False,
    ) -> str:
        """Save template to file."""
        if filename is None:
            # Generate filename from template name
            safe_name = "".join(
                c for c in template.metadata.name if c.isalnum() or c in (" ", "-", "_")
            ).rstrip()
            filename = safe_name.replace(" ", "_").lower()

        # Ensure filename is safe
        filename = os.path.basename(filename)
        if not filename:
            filename = f"template_{template.metadata.id}"

        # Add extension if not present
        if not filename.endswith(f".{format.value}"):
            filename += f".{format.value}"

        filepath = os.path.join(self.template_dir, filename)

        # Check for overwrite protection
        if os.path.exists(filepath) and not overwrite:
            raise FileExistsError(
                f"Template file {filepath} already exists. Use overwrite=True to replace."
            )

        # Update modification date
        template.metadata.modified_date = time.strftime("%Y-%m-%d %H:%M:%S")
        template.file_path = filepath

        # Prepare template data for saving
        # Convert metadata to dict with proper enum handling
        metadata_dict = asdict(template.metadata)
        # Convert enums to their values
        if "category" in metadata_dict and hasattr(metadata_dict["category"], "value"):
            metadata_dict["category"] = metadata_dict["category"].value

        template_data = {"metadata": metadata_dict, "config": template.config}

        # Save based on format
        with open(filepath, "w") as f:
            if format == TemplateFormat.JSON:
                json.dump(template_data, f, indent=2, ensure_ascii=False)
            else:  # YAML
                yaml.dump(template_data, f, default_flow_style=False, allow_unicode=True)

        return filepath

    def load_template(self, filename: str) -> Optional[EnhancedTemplate]:
        """Load template from file."""
        # Security check - ensure filename is safe
        safe_filename = os.path.basename(filename)
        if not safe_filename or ".." in filename:
            raise ValueError(f"Invalid filename: {filename}")

        # Try different locations and extensions
        possible_paths = [
            filename,  # Exact path if provided
            os.path.join(self.template_dir, safe_filename),
            os.path.join(self.template_dir, safe_filename + ".json"),
            os.path.join(self.template_dir, safe_filename + ".yaml"),
            os.path.join(self.template_dir, safe_filename + ".yml"),
        ]

        for filepath in possible_paths:
            if os.path.exists(filepath):
                try:
                    return self._load_template_file(filepath)
                except Exception as e:
                    print(f"Error loading template from {filepath}: {e}")
                    continue

        return None

    def _load_template_file(self, filepath: str) -> EnhancedTemplate:
        """Load template from specific file path."""
        with open(filepath, "r") as f:
            if filepath.endswith(".json"):
                data = json.load(f)
            else:  # YAML
                data = yaml.safe_load(f)

        # Handle both new format (with metadata) and legacy format
        if "metadata" in data and "config" in data:
            # New enhanced format
            metadata = TemplateMetadata(**data["metadata"])
            config = data["config"]
        else:
            # Legacy format - create metadata
            metadata = TemplateMetadata(
                name=os.path.splitext(os.path.basename(filepath))[0],
                description="Legacy template",
                category=TemplateCategory.IMPORTED,
                source="file_import",
            )
            config = data

            # Try to analyze legacy template
            try:
                if "hash_config" in config:
                    analysis = self.analyzer.analyze_configuration(config["hash_config"])
                    metadata.security_score = analysis.overall_score
                    metadata.security_level = analysis.security_level.name
            except Exception:
                pass

        template = EnhancedTemplate(
            metadata=metadata, config=config, file_path=filepath, is_built_in=False
        )

        return template

    def list_templates(self, category: Optional[TemplateCategory] = None) -> List[EnhancedTemplate]:
        """List all available templates."""
        templates = []

        # Add built-in templates
        for name, data in self.BUILT_IN_TEMPLATES.items():
            metadata = TemplateMetadata(**data["metadata"])
            template = EnhancedTemplate(metadata=metadata, config=data["config"], is_built_in=True)
            templates.append(template)

        # Add file-based templates
        if os.path.exists(self.template_dir):
            for filename in os.listdir(self.template_dir):
                if filename.endswith((".json", ".yaml", ".yml")):
                    try:
                        template = self._load_template_file(
                            os.path.join(self.template_dir, filename)
                        )
                        templates.append(template)
                    except Exception:
                        continue  # Skip invalid templates

        # Filter by category if specified
        if category is not None:
            templates = [t for t in templates if t.metadata.category == category]

        # Sort by security score (descending) then name
        templates.sort(key=lambda t: (-t.metadata.security_score, t.metadata.name))

        return templates

    def get_template_by_name(self, name: str) -> Optional[EnhancedTemplate]:
        """Get template by name."""
        # Check built-in templates first
        if name in self.BUILT_IN_TEMPLATES:
            data = self.BUILT_IN_TEMPLATES[name]
            metadata = TemplateMetadata(**data["metadata"])
            return EnhancedTemplate(metadata=metadata, config=data["config"], is_built_in=True)

        # Check file-based templates
        all_templates = self.list_templates()
        for template in all_templates:
            if template.metadata.name.lower() == name.lower():
                return template

        return None

    def compare_templates(
        self, template1: EnhancedTemplate, template2: EnhancedTemplate
    ) -> Dict[str, Any]:
        """Compare two templates and provide analysis."""
        comparison = {
            "templates": {
                "template1": {
                    "name": template1.metadata.name,
                    "security_score": template1.metadata.security_score,
                    "security_level": template1.metadata.security_level,
                    "use_cases": template1.metadata.use_cases,
                },
                "template2": {
                    "name": template2.metadata.name,
                    "security_score": template2.metadata.security_score,
                    "security_level": template2.metadata.security_level,
                    "use_cases": template2.metadata.use_cases,
                },
            },
            "security_comparison": {},
            "performance_comparison": {},
            "recommendations": [],
        }

        # Security comparison
        score_diff = template1.metadata.security_score - template2.metadata.security_score
        if abs(score_diff) < 0.5:
            comparison["security_comparison"]["verdict"] = "Similar security levels"
        elif score_diff > 0:
            comparison["security_comparison"][
                "verdict"
            ] = f"{template1.metadata.name} provides higher security"
        else:
            comparison["security_comparison"][
                "verdict"
            ] = f"{template2.metadata.name} provides higher security"

        comparison["security_comparison"]["score_difference"] = score_diff

        # Analyze configurations to get performance data
        try:
            analysis1 = self.analyzer.analyze_configuration(template1.config.get("hash_config", {}))
            analysis2 = self.analyzer.analyze_configuration(template2.config.get("hash_config", {}))

            perf1 = analysis1.performance_assessment["overall_score"]
            perf2 = analysis2.performance_assessment["overall_score"]

            comparison["performance_comparison"]["template1_score"] = perf1
            comparison["performance_comparison"]["template2_score"] = perf2

            if abs(perf1 - perf2) < 0.5:
                comparison["performance_comparison"][
                    "verdict"
                ] = "Similar performance characteristics"
            elif perf1 > perf2:
                comparison["performance_comparison"][
                    "verdict"
                ] = f"{template1.metadata.name} offers better performance"
            else:
                comparison["performance_comparison"][
                    "verdict"
                ] = f"{template2.metadata.name} offers better performance"

        except Exception:
            comparison["performance_comparison"]["verdict"] = "Performance comparison unavailable"

        return comparison

    def recommend_templates(
        self, use_case: str, max_results: int = 3
    ) -> List[Tuple[EnhancedTemplate, str]]:
        """Recommend templates for a specific use case."""
        all_templates = self.list_templates()
        recommendations = []

        for template in all_templates:
            score = 0
            reason_parts = []

            # Use case match
            if use_case in template.metadata.use_cases:
                score += 10
                reason_parts.append("perfect use case match")
            elif any(uc in template.metadata.use_cases for uc in [use_case]):
                score += 5
                reason_parts.append("related use case")

            # Security level appropriateness
            if use_case in ["compliance", "archival"] and template.metadata.security_score >= 7.0:
                score += 8
                reason_parts.append("high security for sensitive use case")
            elif use_case == "personal" and 4.0 <= template.metadata.security_score <= 7.0:
                score += 6
                reason_parts.append("balanced security for personal use")
            elif (
                use_case in ["business", "development"] and template.metadata.security_score >= 5.0
            ):
                score += 7
                reason_parts.append("good security for business use")

            # Tag matching
            use_case_tags = {
                "personal": ["balanced", "lightweight"],
                "business": ["recommended", "balanced"],
                "compliance": ["high_security", "comprehensive"],
                "archival": ["maximum_security", "comprehensive"],
                "development": ["fast", "lightweight"],
                "testing": ["fast", "basic_security"],
            }

            relevant_tags = use_case_tags.get(use_case, [])
            matching_tags = set(template.metadata.tags) & set(relevant_tags)
            if matching_tags:
                score += len(matching_tags) * 2
                reason_parts.append(f"suitable characteristics: {', '.join(matching_tags)}")

            if score > 0:
                reason = "; ".join(reason_parts).capitalize()
                recommendations.append((template, reason, score))

        # Sort by score (descending) and take top results
        recommendations.sort(key=lambda x: x[2], reverse=True)
        return [(template, reason) for template, reason, _ in recommendations[:max_results]]

    def validate_template(self, template: EnhancedTemplate) -> Tuple[bool, List[str]]:
        """Validate template configuration."""
        errors = []

        # Check basic structure
        if not template.config:
            errors.append("Template config is empty")
            return False, errors

        if "hash_config" not in template.config:
            errors.append("Missing 'hash_config' section")
            return False, errors

        hash_config = template.config["hash_config"]

        # Check for at least one enabled security mechanism
        has_hash = any(
            isinstance(hash_config.get(h), int) and hash_config.get(h, 0) > 0
            for h in ["sha256", "sha512", "blake2b", "blake3"]
        )
        has_kdf = any(
            hash_config.get(kdf, {}).get("enabled", False)
            if isinstance(hash_config.get(kdf), dict)
            else False
            for kdf in ["argon2", "scrypt", "balloon"]
        )
        has_pbkdf2 = (
            isinstance(hash_config.get("pbkdf2_iterations"), int)
            and hash_config.get("pbkdf2_iterations", 0) > 0
        )

        if not (has_hash or has_kdf or has_pbkdf2):
            errors.append("Template must have at least one enabled hash function or KDF")

        # Check algorithm if specified
        algorithm = hash_config.get("algorithm")
        if algorithm:
            valid_algorithms = [
                "fernet",
                "aes-gcm",
                "aes-gcm-siv",
                "aes-siv",
                "aes-ocb3",
                "chacha20-poly1305",
                "xchacha20-poly1305",
            ]
            if algorithm not in valid_algorithms:
                errors.append(f"Unknown algorithm: {algorithm}")

        # Validate numeric parameters
        numeric_fields = {
            "sha256": (0, 10000000),
            "sha512": (0, 10000000),
            "blake2b": (0, 10000000),
            "pbkdf2_iterations": (0, 10000000),
        }

        for field, (min_val, max_val) in numeric_fields.items():
            if field in hash_config:
                value = hash_config[field]
                if isinstance(value, int):
                    if value < min_val or value > max_val:
                        errors.append(
                            f"{field} value {value} outside valid range [{min_val}, {max_val}]"
                        )
                elif value is not None:
                    errors.append(f"{field} must be an integer or None")

        return len(errors) == 0, errors

    def generate_template_report(self, template: EnhancedTemplate) -> Dict[str, Any]:
        """Generate comprehensive report for a template."""
        report = {
            "metadata": asdict(template.metadata),
            "configuration": template.config,
            "validation": {},
            "analysis": {},
            "recommendations": [],
        }

        # Validate template
        is_valid, validation_errors = self.validate_template(template)
        report["validation"] = {"is_valid": is_valid, "errors": validation_errors}

        # Analyze template
        try:
            if "hash_config" in template.config:
                analysis = self.analyzer.analyze_configuration(template.config["hash_config"])
                report["analysis"] = {
                    "overall_score": analysis.overall_score,
                    "security_level": analysis.security_level.name,
                    "performance": analysis.performance_assessment,
                    "compatibility": analysis.compatibility_matrix,
                    "future_proofing": analysis.future_proofing,
                    "recommendations": [
                        {
                            "priority": rec.priority.value,
                            "title": rec.title,
                            "description": rec.description,
                            "action": rec.action,
                        }
                        for rec in analysis.recommendations
                    ],
                }
        except Exception as e:
            report["analysis"]["error"] = str(e)

        return report

    def analyze_template(
        self,
        template: EnhancedTemplate,
        use_case: Optional[str] = None,
        compliance_requirements: Optional[List[str]] = None,
    ):
        """Analyze a template's configuration for security, performance, and compatibility."""
        from .config_analyzer import ConfigurationAnalyzer

        try:
            analyzer = ConfigurationAnalyzer()
            return analyzer.analyze_configuration(
                template.config, use_case, compliance_requirements
            )
        except Exception as e:
            # Return a minimal analysis object in case of error
            from .config_analyzer import ConfigurationAnalysis

            return ConfigurationAnalysis(
                security_score=0.0,
                performance_score=0.0,
                compatibility_score=0.0,
                security_level="UNKNOWN",
                performance_assessment="Unknown",
                compatibility_matrix={},
                future_proofing={},
                recommendations=[],
            )

    def delete_template(self, template: EnhancedTemplate) -> bool:
        """Delete a template file."""
        if template.is_built_in:
            raise ValueError("Cannot delete built-in templates")

        if template.file_path and os.path.exists(template.file_path):
            try:
                os.remove(template.file_path)
                return True
            except Exception:
                return False

        return False


def create_template_manager(template_dir: Optional[str] = None) -> TemplateManager:
    """Factory function to create a template manager."""
    return TemplateManager(template_dir)
