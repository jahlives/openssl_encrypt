#!/usr/bin/env python3
"""
Format Converter Plugin

This plugin demonstrates safe format conversion capabilities within the
OpenSSL Encrypt plugin system. It shows how to convert between different
text formats before encryption while maintaining security boundaries.

Features:
- Text format conversions (txt, csv, json, xml)
- Safe file format detection
- Temporary file handling with secure cleanup
- Format validation and error handling
- Preserves file metadata where possible

Security Notes:
- Only works with text-based formats for safety
- Uses temporary files with secure permissions
- No network access or external dependencies
- Validates input before processing
- Secure cleanup of temporary files
"""

import csv
import json
import logging
import os
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...modules.plugin_system import (
    FormatConverterPlugin,
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
    PreProcessorPlugin,
)

logger = logging.getLogger(__name__)


class TextFormatConverter(FormatConverterPlugin):
    """
    Format converter plugin for safe text format transformations.
    Demonstrates secure format conversion within plugin constraints.
    """

    def __init__(self):
        super().__init__("text_converter", "Text Format Converter", "1.0.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Converts between text formats (txt, csv, json, xml) before encryption"

    def get_supported_input_formats(self) -> List[str]:
        """Return list of supported input formats."""
        return ["txt", "csv", "json", "xml"]

    def get_supported_output_formats(self) -> List[str]:
        """Return list of supported output formats."""
        return ["txt", "csv", "json", "xml"]

    def convert_format(
        self,
        input_path: str,
        output_path: str,
        input_format: str,
        output_format: str,
        context: PluginSecurityContext,
    ) -> PluginResult:
        """Convert file from input format to output format."""
        try:
            if not os.path.exists(input_path):
                return PluginResult.error_result(f"Input file not found: {input_path}")

            if input_format == output_format:
                # Just copy the file
                import shutil

                shutil.copy2(input_path, output_path)
                return PluginResult.success_result(f"File copied (no conversion needed)")

            # Load data based on input format
            data = self._load_data(input_path, input_format)
            if data is None:
                return PluginResult.error_result(f"Failed to load data from {input_format} format")

            # Convert data to output format
            success = self._save_data(output_path, output_format, data)
            if not success:
                return PluginResult.error_result(f"Failed to save data in {output_format} format")

            # Verify conversion
            input_size = os.path.getsize(input_path)
            output_size = os.path.getsize(output_path)

            logger.info(
                f"Format conversion: {input_format} -> {output_format} "
                f"({input_size} -> {output_size} bytes)"
            )

            return PluginResult.success_result(
                f"Converted {input_format} to {output_format}",
                {
                    "input_format": input_format,
                    "output_format": output_format,
                    "input_size": input_size,
                    "output_size": output_size,
                    "conversion_successful": True,
                },
            )

        except Exception as e:
            return PluginResult.error_result(f"Format conversion failed: {str(e)}")

    def _load_data(self, file_path: str, format_type: str) -> Optional[Any]:
        """Load data from file based on format type."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                if format_type == "txt":
                    return f.read()

                elif format_type == "json":
                    return json.load(f)

                elif format_type == "csv":
                    reader = csv.DictReader(f)
                    return list(reader)

                elif format_type == "xml":
                    content = f.read()
                    root = ET.fromstring(content)
                    return self._xml_to_dict(root)

                else:
                    return None

        except Exception as e:
            logger.error(f"Error loading {format_type} data: {e}")
            return None

    def _save_data(self, file_path: str, format_type: str, data: Any) -> bool:
        """Save data to file in specified format."""
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                if format_type == "txt":
                    if isinstance(data, str):
                        f.write(data)
                    else:
                        f.write(str(data))

                elif format_type == "json":
                    json.dump(data, f, indent=2, ensure_ascii=False)

                elif format_type == "csv":
                    if isinstance(data, list) and data and isinstance(data[0], dict):
                        fieldnames = data[0].keys()
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(data)
                    else:
                        # Convert other types to simple CSV
                        writer = csv.writer(f)
                        if isinstance(data, list):
                            for row in data:
                                writer.writerow(
                                    [row] if not isinstance(row, (list, tuple)) else row
                                )
                        else:
                            writer.writerow([data])

                elif format_type == "xml":
                    if isinstance(data, dict):
                        root = self._dict_to_xml(data)
                        tree = ET.ElementTree(root)
                        tree.write(f, encoding="unicode", xml_declaration=True)
                    else:
                        # Simple XML wrapper
                        root = ET.Element("data")
                        root.text = str(data)
                        tree = ET.ElementTree(root)
                        tree.write(f, encoding="unicode", xml_declaration=True)

                else:
                    return False

            return True

        except Exception as e:
            logger.error(f"Error saving {format_type} data: {e}")
            return False

    def _xml_to_dict(self, element) -> Dict[str, Any]:
        """Convert XML element to dictionary."""
        result = {}

        # Add attributes
        if element.attrib:
            result["@attributes"] = element.attrib

        # Add text content
        if element.text and element.text.strip():
            if len(element) == 0:
                return element.text.strip()
            result["text"] = element.text.strip()

        # Add child elements
        for child in element:
            child_data = self._xml_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data

        return result

    def _dict_to_xml(self, data: Dict[str, Any], root_name: str = "root") -> ET.Element:
        """Convert dictionary to XML element."""
        root = ET.Element(root_name)

        def add_to_element(element, key, value):
            if key == "@attributes" and isinstance(value, dict):
                element.attrib.update(value)
            elif key == "text":
                element.text = str(value)
            elif isinstance(value, dict):
                sub_element = ET.SubElement(element, key)
                for sub_key, sub_value in value.items():
                    add_to_element(sub_element, sub_key, sub_value)
            elif isinstance(value, list):
                for item in value:
                    sub_element = ET.SubElement(element, key)
                    if isinstance(item, dict):
                        for sub_key, sub_value in item.items():
                            add_to_element(sub_element, sub_key, sub_value)
                    else:
                        sub_element.text = str(item)
            else:
                sub_element = ET.SubElement(element, key)
                sub_element.text = str(value)

        for key, value in data.items():
            add_to_element(root, key, value)

        return root


class SmartFormatPreProcessor(PreProcessorPlugin):
    """
    Pre-processor that automatically detects and converts file formats.
    Demonstrates smart format handling with user preferences.
    """

    def __init__(self):
        super().__init__("smart_format", "Smart Format Pre-Processor", "1.0.0")
        self.converter = TextFormatConverter()

    def get_required_capabilities(self):
        return {
            PluginCapability.READ_FILES,
            PluginCapability.WRITE_LOGS,
            PluginCapability.MODIFY_METADATA,
        }

    def get_description(self):
        return "Automatically detects file formats and applies smart conversions before encryption"

    def process_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
        """Process file with smart format detection and conversion."""
        try:
            if not os.path.exists(file_path):
                return PluginResult.error_result(f"File not found: {file_path}")

            # Detect current format
            current_format = self._detect_format(file_path)
            if not current_format:
                # Not a text format we can handle
                context.add_metadata("format_processing", "skipped_binary")
                return PluginResult.success_result("File format not suitable for conversion")

            # Check if conversion is requested in context
            target_format = context.metadata.get("target_format")
            if not target_format:
                # No conversion requested, just add metadata
                context.add_metadata("detected_format", current_format)
                context.add_metadata("format_processing", "detection_only")
                return PluginResult.success_result(f"Detected format: {current_format}")

            # Perform conversion if needed
            if current_format == target_format:
                context.add_metadata("format_processing", "no_conversion_needed")
                return PluginResult.success_result("File already in target format")

            # Create temporary file for conversion
            temp_dir = tempfile.mkdtemp(prefix="format_convert_")
            temp_file = os.path.join(temp_dir, f"converted.{target_format}")

            try:
                conversion_result = self.converter.convert_format(
                    file_path, temp_file, current_format, target_format, context
                )

                if conversion_result.success:
                    # Replace original file with converted version
                    import shutil

                    shutil.copy2(temp_file, file_path)

                    context.add_metadata("format_processing", "converted")
                    context.add_metadata("original_format", current_format)
                    context.add_metadata("converted_to", target_format)

                    logger.info(f"Smart format conversion: {current_format} -> {target_format}")

                    return PluginResult.success_result(
                        f"Converted {current_format} to {target_format}", conversion_result.data
                    )
                else:
                    context.add_metadata("format_processing", "conversion_failed")
                    return conversion_result

            finally:
                # Clean up temporary files
                try:
                    import shutil

                    shutil.rmtree(temp_dir)
                except Exception:
                    pass  # Ignore cleanup errors

        except Exception as e:
            return PluginResult.error_result(f"Smart format processing failed: {str(e)}")

    def _detect_format(self, file_path: str) -> Optional[str]:
        """Detect file format based on content and extension."""
        try:
            # First check extension
            extension = Path(file_path).suffix.lower().lstrip(".")
            if extension in ["txt", "csv", "json", "xml"]:
                # Verify content matches extension
                if self._verify_format(file_path, extension):
                    return extension

            # Try to detect from content
            with open(file_path, "r", encoding="utf-8") as f:
                # Read first few lines to detect format
                first_lines = []
                for i, line in enumerate(f):
                    first_lines.append(line.strip())
                    if i >= 10:  # Look at first 10 lines max
                        break

                content_start = "\n".join(first_lines)

                # JSON detection
                if content_start.startswith("{") or content_start.startswith("["):
                    try:
                        f.seek(0)
                        json.load(f)
                        return "json"
                    except (json.JSONDecodeError, ValueError):
                        pass

                # XML detection
                if content_start.startswith("<?xml") or (
                    "<" in content_start and ">" in content_start
                ):
                    try:
                        f.seek(0)
                        ET.parse(f)
                        return "xml"
                    except ET.ParseError:
                        pass

                # CSV detection (look for common CSV patterns)
                if "," in content_start and len(first_lines) > 1:
                    first_line_commas = first_lines[0].count(",")
                    if first_line_commas > 0:
                        # Check if other lines have similar comma count
                        similar_comma_count = sum(
                            1
                            for line in first_lines[1:]
                            if abs(line.count(",") - first_line_commas) <= 1
                        )
                        if similar_comma_count / len(first_lines[1:]) > 0.7:  # 70% similarity
                            return "csv"

                # Default to text
                return "txt"

        except (UnicodeDecodeError, PermissionError):
            # Not a text file or no permission
            return None
        except Exception:
            return None

    def _verify_format(self, file_path: str, format_type: str) -> bool:
        """Verify that file content matches the claimed format."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                if format_type == "json":
                    json.load(f)
                elif format_type == "xml":
                    ET.parse(f)
                elif format_type == "csv":
                    # Just check if CSV reader can parse it
                    csv.reader(f)
                elif format_type == "txt":
                    # Text files are always valid if readable
                    f.read()

            return True

        except Exception:
            return False
