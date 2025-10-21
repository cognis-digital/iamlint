"""IAMLINT — Lint cloud IAM policies (AWS/GCP/Azure JSON) for least-privilege violations."""
from iamlint.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
