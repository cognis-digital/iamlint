#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> lint . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Forward iamlint JSON findings to a webhook URL.",
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https).")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra header in 'Key: Value' format.")
    args = ap.parse_args()

    # Validate the URL scheme before attempting a network call.
    if not args.url.startswith(("http://", "https://")):
        print(f"error: --url must start with http:// or https://: {args.url!r}",
              file=sys.stderr)
        return 2

    payload = sys.stdin.buffer.read()
    if not payload.strip():
        print("error: no payload received on stdin", file=sys.stderr)
        return 2

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        if not k.strip():
            print(f"error: invalid header (no key): {h!r}", file=sys.stderr)
            return 2
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(f"webhook HTTP error {exc.code}: {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook connection error: {exc.reason}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
