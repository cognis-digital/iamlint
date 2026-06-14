"""IAMLINT MCP server — exposes iamlint_scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json

from iamlint.core import lint_document, summarize


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-iamlint[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-iamlint[mcp]'")
        return 1
    app = FastMCP("iamlint")

    @app.tool()
    def iamlint_scan(policy_json: str) -> str:
        """Lint cloud IAM policies (AWS/GCP/Azure JSON) for least-privilege violations.

        Args:
            policy_json: Raw IAM policy document as a JSON string.

        Returns:
            JSON string with tool metadata, summary counts, and findings list.
        """
        if not policy_json or not policy_json.strip():
            return json.dumps({"error": "policy_json must be a non-empty JSON string"})
        findings = lint_document(policy_json)
        counts = summarize(findings)
        from iamlint import TOOL_NAME, TOOL_VERSION
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "summary": counts,
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(payload, indent=2)

    app.run()
    return 0
