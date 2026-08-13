#!/usr/bin/env python3
"""Shared JSON envelope for machine-readable command output (gitlab#268).

Every NEW ``--json`` endpoint prints exactly one document on stdout:

    {"status": "ok",    "data":  {...}}          on success
    {"status": "error", "error": {"message": ...}} on failure

Rules (docs/total-json-output-plan.md): the document is emitted once, on
stdout only; progress/prompts/human reports stay on stderr; exit codes are
unchanged; secrets may appear in the stdout document and nowhere else; the
content is deliberately NOT display-sanitized (gitlab#183 — display safety is
the consumer's decode-boundary job). Endpoints that predate the envelope
(e.g. ``list-available-algorithms``) keep their historical shape.
"""

import json
from typing import Any

# One document per invocation (gitlab#270 F4): the emitters record that a
# document went out so the CLI's exit path can add a fallback error envelope
# when a JSON-mode operation fails without ever reaching an emitter.
_document_emitted = False


def document_emitted() -> bool:
    """True once emit_json/emit_json_error has printed a document."""
    return _document_emitted


def reset_emitted() -> None:
    """Reset the emitted flag (start of an invocation; in-process tests)."""
    global _document_emitted
    _document_emitted = False


def emit_json(data: Any) -> None:
    """Print the success envelope for ``data`` as one stdout JSON document.

    Args:
        data: JSON-serializable payload for the ``data`` field.
    """
    global _document_emitted
    _document_emitted = True
    print(json.dumps({"status": "ok", "data": data}), flush=True)


def emit_json_error(message: str) -> None:
    """Print the error envelope with ``message`` as one stdout JSON document.

    Args:
        message: Human-readable error description (no secrets).
    """
    global _document_emitted
    _document_emitted = True
    print(json.dumps({"status": "error", "error": {"message": str(message)}}), flush=True)
