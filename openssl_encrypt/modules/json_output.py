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


def emit_json(data: Any) -> None:
    """Print the success envelope for ``data`` as one stdout JSON document.

    Args:
        data: JSON-serializable payload for the ``data`` field.
    """
    print(json.dumps({"status": "ok", "data": data}), flush=True)


def emit_json_error(message: str) -> None:
    """Print the error envelope with ``message`` as one stdout JSON document.

    Args:
        message: Human-readable error description (no secrets).
    """
    print(json.dumps({"status": "error", "error": {"message": str(message)}}), flush=True)
