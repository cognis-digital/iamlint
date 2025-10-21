"""IAMLINT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from iamlint.core import scan, to_json

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
    def iamlint_scan(target: str) -> str:
        """Lint cloud IAM policies (AWS/GCP/Azure JSON) for least-privilege violations. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
