"""Smoke tests for IAMLINT. Standard library only, no network."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from iamlint import TOOL_NAME, TOOL_VERSION, lint_document, summarize  # noqa: E402
from iamlint.core import Severity, detect_provider, lint_policy  # noqa: E402
from iamlint import cli  # noqa: E402


AWS_ADMIN = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"}
    ],
})

AWS_TIGHT = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "Read", "Effect": "Allow",
         "Action": ["s3:GetObject"],
         "Resource": "arn:aws:s3:::my-bucket/*",
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    ],
})

GCP_OWNER = json.dumps({
    "bindings": [
        {"role": "roles/owner", "members": ["user:eve@example.com"]},
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
    ]
})

AZURE_WILD = json.dumps({
    "Properties": {
        "roleName": "BadRole",
        "permissions": [{"actions": ["*"], "dataActions": []}],
        "assignableScopes": ["/"],
    }
})


class TestCore(unittest.TestCase):
    def test_version_metadata(self):
        self.assertEqual(TOOL_NAME, "iamlint")
        self.assertTrue(TOOL_VERSION)

    def test_detect_provider(self):
        self.assertEqual(detect_provider(json.loads(AWS_ADMIN)), "aws")
        self.assertEqual(detect_provider(json.loads(GCP_OWNER)), "gcp")
        self.assertEqual(detect_provider(json.loads(AZURE_WILD)), "azure")

    def test_aws_admin_is_critical(self):
        findings = lint_document(AWS_ADMIN)
        ids = {f.rule_id for f in findings}
        self.assertIn("AWS001", ids)
        self.assertTrue(any(f.severity == Severity.CRITICAL for f in findings))

    def test_aws_tight_policy_low_noise(self):
        findings = lint_document(AWS_TIGHT)
        # A well-scoped, conditioned policy should not produce HIGH+ findings.
        self.assertFalse(
            any(Severity.rank(f.severity) >= Severity.rank(Severity.HIGH)
                for f in findings))

    def test_aws_passrole_and_public_principal(self):
        doc = {
            "Statement": [
                {"Sid": "a", "Effect": "Allow",
                 "Action": ["iam:PassRole"], "Resource": "*"},
                {"Sid": "b", "Effect": "Allow", "Principal": "*",
                 "Action": ["s3:GetObject"], "Resource": "arn:x"},
            ]
        }
        ids = {f.rule_id for f in lint_policy(doc)}
        self.assertIn("AWS007", ids)
        self.assertIn("AWS009", ids)

    def test_gcp_owner_and_public(self):
        ids = {f.rule_id for f in lint_document(GCP_OWNER)}
        self.assertIn("GCP001", ids)
        self.assertIn("GCP002", ids)

    def test_azure_wildcard_and_root_scope(self):
        ids = {f.rule_id for f in lint_document(AZURE_WILD)}
        self.assertIn("AZ001", ids)
        self.assertIn("AZ005", ids)

    def test_invalid_json(self):
        findings = lint_document("{not json")
        self.assertEqual(findings[0].rule_id, "GEN002")

    def test_summarize_counts(self):
        findings = lint_document(AWS_ADMIN)
        counts = summarize(findings)
        self.assertEqual(counts["TOTAL"], len(findings))
        self.assertGreaterEqual(counts[Severity.CRITICAL], 1)

    def test_findings_sorted_by_severity(self):
        findings = lint_document(AWS_ADMIN)
        ranks = [Severity.rank(f.severity) for f in findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


class TestCli(unittest.TestCase):
    def _write(self, text):
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(lambda: os.remove(path))
        return path

    def test_cli_nonzero_on_findings(self):
        path = self._write(AWS_ADMIN)
        self.assertEqual(cli.main(["lint", path]), 1)

    def test_cli_zero_on_clean_with_threshold(self):
        path = self._write(AWS_TIGHT)
        # Tight policy only emits INFO; fail-on=high should pass.
        self.assertEqual(cli.main(["lint", path, "--fail-on", "high"]), 0)

    def test_cli_json_output(self):
        path = self._write(GCP_OWNER)
        out = self._write("")
        rc = cli.main(["lint", path, "--format", "json", "-o", out])
        self.assertEqual(rc, 1)
        with open(out, encoding="utf-8") as fh:
            payload = json.load(fh)
        self.assertEqual(payload["tool"], "iamlint")
        self.assertIn("findings", payload)

    def test_cli_html_output(self):
        path = self._write(AZURE_WILD)
        out = self._write("")
        rc = cli.main(["lint", path, "--format", "html", "-o", out])
        self.assertEqual(rc, 1)
        with open(out, encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("IAMLINT", content)

    def test_cli_never_fails_with_never(self):
        path = self._write(AWS_ADMIN)
        self.assertEqual(cli.main(["lint", path, "--fail-on", "never"]), 0)


class TestHardening(unittest.TestCase):
    """Edge-case and error-path tests added during production hardening."""

    def _write(self, text, encoding="utf-8"):
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(text)
        self.addCleanup(lambda: os.remove(path))
        return path

    # -- CLI error paths --

    def test_cli_missing_file_returns_exit_2(self):
        """A missing input file must print to stderr and return exit code 2."""
        rc = cli.main(["lint", "/nonexistent/path/does_not_exist_xyz.json"])
        self.assertEqual(rc, 2)

    def test_cli_no_subcommand_returns_exit_2(self):
        """Invoking with no subcommand must return 2, not raise an exception."""
        rc = cli.main([])
        self.assertEqual(rc, 2)

    def test_cli_malformed_json_returns_nonzero(self):
        """A syntactically invalid JSON file must produce a clean HIGH finding."""
        path = self._write("{not valid json!!!")
        rc = cli.main(["lint", path])
        self.assertNotEqual(rc, 0)

    def test_cli_empty_file_returns_nonzero(self):
        """An empty file must produce a clean HIGH finding, not a traceback."""
        path = self._write("")
        rc = cli.main(["lint", path])
        self.assertNotEqual(rc, 0)

    def test_cli_utf8_bom_file_parsed_correctly(self):
        """A UTF-8 BOM file (common on Windows) must be parsed without error."""
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        })
        path = self._write(policy, encoding="utf-8-sig")
        rc = cli.main(["lint", path])
        # Should produce findings (not a GEN002 JSON error) and exit non-zero.
        self.assertEqual(rc, 1)

    def test_cli_json_format_on_empty_input_is_valid_json(self):
        """Even on empty input, --format json must emit valid JSON."""
        path = self._write("")
        out_fd, out_path = __import__("tempfile").mkstemp(suffix=".json")
        os.close(out_fd)
        self.addCleanup(lambda: os.remove(out_path))
        cli.main(["lint", path, "--format", "json", "-o", out_path])
        with open(out_path, encoding="utf-8") as fh:
            payload = json.load(fh)
        self.assertIn("findings", payload)

    # -- Core error/edge paths --

    def test_lint_document_empty_string(self):
        """Empty string input must return a GEN003 finding, not raise."""
        from iamlint.core import lint_document
        findings = lint_document("")
        self.assertEqual(findings[0].rule_id, "GEN003")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_lint_document_whitespace_only(self):
        """Whitespace-only input must return GEN003."""
        from iamlint.core import lint_document
        findings = lint_document("   \n\t  ")
        self.assertEqual(findings[0].rule_id, "GEN003")

    def test_detect_provider_operator_precedence(self):
        """detect_provider must return 'aws' for a doc with only Statement key."""
        from iamlint.core import detect_provider
        # Before the fix, "Statement" in doc was shadowed by the or/and precedence bug.
        doc = {"Statement": []}
        self.assertEqual(detect_provider(doc), "aws")
        # A doc with only Version (no Statement) must NOT be detected as aws.
        doc2 = {"Version": "2012-10-17"}
        self.assertNotEqual(detect_provider(doc2), "aws")

    def test_mcp_server_module_imports_cleanly(self):
        """mcp_server.py must import without ImportError (broken scan/to_json refs)."""
        import importlib
        import iamlint.mcp_server  # noqa: F401
        # Re-import to confirm it's not cached from a broken state.
        importlib.reload(iamlint.mcp_server)


if __name__ == "__main__":
    unittest.main()
