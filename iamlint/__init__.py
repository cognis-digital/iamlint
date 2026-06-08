"""IAMLINT - Cloud IAM policy least-privilege linter.

Lints AWS / GCP / Azure IAM policy JSON for over-permissive grants,
wildcard abuse, privilege-escalation patterns and missing guardrails.

Defensive analysis only: it reads policy documents you own and reports
findings. It performs no network access and grants no access.
"""
from iamlint.core import (
    Finding,
    Severity,
    detect_provider,
    lint_policy,
    lint_document,
    summarize,
)

TOOL_NAME = "iamlint"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "Severity",
    "detect_provider",
    "lint_policy",
    "lint_document",
    "summarize",
]
