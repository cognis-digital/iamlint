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


if __name__ == "__main__":
    unittest.main()
