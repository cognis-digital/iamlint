"""Command-line interface for IAMLINT."""
from __future__ import annotations

import argparse
import html as _html
import json
import sys
from typing import Sequence

from iamlint import TOOL_NAME, TOOL_VERSION
from iamlint.core import Finding, Severity, lint_document, summarize

_SEV_COLORS = {
    Severity.CRITICAL: "#8b0000",
    Severity.HIGH: "#d9534f",
    Severity.MEDIUM: "#f0ad4e",
    Severity.LOW: "#5bc0de",
    Severity.INFO: "#777777",
}


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _render_table(findings: list[Finding], counts: dict, path: str) -> str:
    lines = []
    lines.append(f"IAMLINT {TOOL_VERSION} - report for {path}")
    lines.append("=" * 64)
    if not findings:
        lines.append("No findings. Policy passes least-privilege checks.")
        return "\n".join(lines)
    width = max(len(f.rule_id) for f in findings)
    for f in findings:
        lines.append(f"[{f.severity:<8}] {f.rule_id:<{width}}  {f.title}")
        lines.append(f"           at {f.location}  ({f.provider})")
        lines.append(f"           {f.detail}")
        lines.append(f"           fix: {f.remediation}")
        lines.append("")
    lines.append("-" * 64)
    lines.append(
        "Summary: "
        + "  ".join(
            f"{s}={counts.get(s, 0)}"
            for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                      Severity.LOW, Severity.INFO)
        )
        + f"  TOTAL={counts.get('TOTAL', 0)}"
    )
    return "\n".join(lines)


def _render_json(findings: list[Finding], counts: dict, path: str) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "source": path,
        "summary": counts,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def _render_html(findings: list[Finding], counts: dict, path: str) -> str:
    e = _html.escape
    rows = []
    for f in findings:
        color = _SEV_COLORS.get(f.severity, "#777")
        rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{color}'>{e(f.severity)}</span></td>"
            f"<td class='mono'>{e(f.rule_id)}</td>"
            f"<td><strong>{e(f.title)}</strong><div class='detail'>{e(f.detail)}</div>"
            f"<div class='fix'>Fix: {e(f.remediation)}</div></td>"
            f"<td class='mono'>{e(f.location)}</td>"
            f"<td>{e(f.provider)}</td>"
            "</tr>"
        )
    summary_cells = "".join(
        f"<div class='card' style='border-top:4px solid {_SEV_COLORS.get(s, '#777')}'>"
        f"<div class='num'>{counts.get(s, 0)}</div><div class='lbl'>{e(s)}</div></div>"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                  Severity.LOW, Severity.INFO)
    )
    body = (
        "<p class='clean'>No findings. Policy passes least-privilege checks.</p>"
        if not findings else
        "<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th>"
        "<th>Location</th><th>Provider</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
    )
    return f"""<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>IAMLINT report - {e(path)}</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
    margin:0;background:#0f1115;color:#e6e6e6;}}
  header{{padding:24px 32px;background:#161a22;border-bottom:1px solid #2a2f3a;}}
  header h1{{margin:0;font-size:20px;}}
  header .sub{{color:#9aa4b2;font-size:13px;margin-top:4px;}}
  .summary{{display:flex;gap:12px;padding:24px 32px;flex-wrap:wrap;}}
  .card{{background:#161a22;border-radius:8px;padding:14px 22px;min-width:90px;
    text-align:center;}}
  .card .num{{font-size:28px;font-weight:700;}}
  .card .lbl{{font-size:11px;color:#9aa4b2;letter-spacing:1px;}}
  table{{width:calc(100% - 64px);margin:0 32px 32px;border-collapse:collapse;
    background:#161a22;border-radius:8px;overflow:hidden;}}
  th,td{{text-align:left;padding:12px 14px;border-bottom:1px solid #232834;
    vertical-align:top;font-size:14px;}}
  th{{background:#1d222c;font-size:12px;letter-spacing:1px;color:#9aa4b2;}}
  .badge{{color:#fff;padding:3px 9px;border-radius:10px;font-size:11px;
    font-weight:700;white-space:nowrap;}}
  .mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;
    color:#bcd;}}
  .detail{{color:#aab2bf;font-size:13px;margin-top:4px;}}
  .fix{{color:#7fd17f;font-size:12px;margin-top:4px;}}
  .clean{{padding:32px;color:#7fd17f;font-size:16px;}}
  footer{{padding:16px 32px;color:#6b7280;font-size:12px;}}
</style></head><body>
<header>
  <h1>IAMLINT &mdash; Least-Privilege Report</h1>
  <div class='sub'>Source: {e(path)} &nbsp;&bull;&nbsp; {TOOL_NAME} v{TOOL_VERSION}
   &nbsp;&bull;&nbsp; {counts.get('TOTAL', 0)} finding(s)</div>
</header>
<div class='summary'>{summary_cells}</div>
{body}
<footer>Defensive analysis only. Review findings against your own policies.</footer>
</body></html>"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Lint cloud IAM policies for least-privilege violations.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command")

    lint = sub.add_parser("lint", help="Lint an IAM policy file (or - for stdin).")
    lint.add_argument("path", help="Path to policy JSON, or '-' for stdin.")
    lint.add_argument("--format", choices=["table", "json", "html"],
                      default="table", help="Output format.")
    lint.add_argument("--provider", choices=["aws", "gcp", "azure"],
                      default=None, help="Force provider (default: autodetect).")
    lint.add_argument("-o", "--output", default=None,
                      help="Write report to file instead of stdout.")
    lint.add_argument("--fail-on", choices=["critical", "high", "medium",
                      "low", "info", "any", "never"], default="low",
                      help="Minimum severity that causes a non-zero exit.")
    return parser


_FAIL_THRESHOLDS = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
    "any": 0, "never": 99,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "lint":
        parser.print_help()
        return 2

    try:
        text = _read(args.path)
    except OSError as exc:
        print(f"error: cannot read {args.path}: {exc}", file=sys.stderr)
        return 2

    findings = lint_document(text, args.provider)
    counts = summarize(findings)

    if args.format == "json":
        report = _render_json(findings, counts, args.path)
    elif args.format == "html":
        report = _render_html(findings, counts, args.path)
    else:
        report = _render_table(findings, counts, args.path)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
            print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 2
    else:
        print(report)

    threshold = _FAIL_THRESHOLDS[args.fail_on]
    if args.fail_on == "never":
        return 0
    worst = max((Severity.rank(f.severity) for f in findings), default=-1)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
