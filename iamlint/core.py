"""Core lint engine for IAMLINT.

Parses cloud IAM policy JSON (AWS / GCP / Azure shapes) and emits
least-privilege findings. Standard library only.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}

    @classmethod
    def rank(cls, sev: str) -> int:
        return cls.ORDER.get(sev, 0)


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    location: str
    remediation: str
    provider: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Sensitive / escalation-prone action patterns (provider-agnostic substrings).
_ESCALATION_ACTIONS = {
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:attachrolepolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:passrole",
    "sts:assumerole",
    "lambda:createfunction",
    "lambda:invokefunction",
    "iam:setiampolicy",
    "resourcemanager.projects.setiampolicy",
    "iam.serviceaccounts.actas",
    "iam.serviceaccountkeys.create",
}

_DATA_EXFIL_ACTIONS = {
    "s3:getobject",
    "s3:*",
    "secretsmanager:getsecretvalue",
    "kms:decrypt",
    "dynamodb:*",
    "storage.objects.get",
}


def detect_provider(doc: Any) -> str:
    """Best-effort cloud provider detection from a parsed policy document."""
    if isinstance(doc, dict):
        if "Statement" in doc or "Version" in doc and "Statement" in doc:
            return "aws"
        if "bindings" in doc:
            return "gcp"
        if "Properties" in doc and isinstance(doc.get("Properties"), dict):
            return "azure"
        if "permissions" in doc or "actions" in doc:
            return "azure"
    if isinstance(doc, dict) and "Statement" in doc:
        return "aws"
    return "unknown"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _norm(s: Any) -> str:
    return str(s).strip().lower()


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------
def _lint_aws(doc: dict, findings: list[Finding]) -> None:
    statements = _as_list(doc.get("Statement"))
    if not statements:
        findings.append(Finding(
            "AWS000", Severity.LOW, "No statements found",
            "Policy document has no Statement entries.",
            "$.Statement", "Verify this is a valid IAM policy.", "aws"))
        return

    for i, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue
        loc = f"$.Statement[{i}]"
        sid = stmt.get("Sid", f"#{i}")
        effect = _norm(stmt.get("Effect", "allow"))
        if effect != "allow":
            continue  # Deny statements tighten access; skip permissive checks.

        actions = [_norm(a) for a in _as_list(stmt.get("Action"))]
        not_action = _as_list(stmt.get("NotAction"))
        resources = [str(r) for r in _as_list(stmt.get("Resource"))]
        conditions = stmt.get("Condition")
        principal = stmt.get("Principal")

        wild_action = "*" in actions
        wild_resource = any(r == "*" for r in resources)

        if wild_action and wild_resource:
            findings.append(Finding(
                "AWS001", Severity.CRITICAL,
                "Full administrative wildcard (Action:* on Resource:*)",
                f"Statement '{sid}' allows every action on every resource.",
                loc,
                "Replace with the specific actions and resource ARNs required.",
                "aws"))
        else:
            if wild_action:
                findings.append(Finding(
                    "AWS002", Severity.HIGH, "Wildcard Action (Action:*)",
                    f"Statement '{sid}' allows all actions.",
                    loc, "Enumerate only the actions the principal needs.",
                    "aws"))
            if wild_resource:
                findings.append(Finding(
                    "AWS003", Severity.HIGH, "Wildcard Resource (Resource:*)",
                    f"Statement '{sid}' applies to all resources.",
                    loc, "Scope to specific resource ARNs.", "aws"))

        # Service-level wildcards e.g. s3:*
        for a in actions:
            if a.endswith(":*"):
                findings.append(Finding(
                    "AWS004", Severity.MEDIUM,
                    f"Service-wide action wildcard ({a})",
                    f"Statement '{sid}' grants all actions for service '{a.split(':')[0]}'.",
                    loc, "List individual actions instead of service:*.", "aws"))

        if not_action:
            findings.append(Finding(
                "AWS005", Severity.HIGH, "Allow with NotAction",
                f"Statement '{sid}' uses Allow+NotAction, granting everything except a denylist.",
                loc, "Use explicit Action allowlists, not NotAction with Allow.",
                "aws"))

        # Privilege escalation actions
        for a in actions:
            if a in _ESCALATION_ACTIONS or a == "iam:*":
                sev = Severity.HIGH if not wild_resource else Severity.CRITICAL
                findings.append(Finding(
                    "AWS006", sev, f"Privilege-escalation action ({a})",
                    f"Statement '{sid}' grants '{a}', enabling privilege escalation.",
                    loc,
                    "Restrict to specific roles/policies and add Condition guards.",
                    "aws"))

        # passrole without resource scoping
        if "iam:passrole" in actions and wild_resource:
            findings.append(Finding(
                "AWS007", Severity.CRITICAL, "iam:PassRole on all resources",
                f"Statement '{sid}' allows passing ANY role to a service.",
                loc, "Scope PassRole to specific role ARNs.", "aws"))

        # Sensitive data actions with broad resource and no condition
        if not conditions:
            for a in actions:
                if a in _DATA_EXFIL_ACTIONS and wild_resource:
                    findings.append(Finding(
                        "AWS008", Severity.MEDIUM,
                        f"Unconditioned sensitive data access ({a})",
                        f"Statement '{sid}' grants '{a}' on all resources with no Condition.",
                        loc,
                        "Add Condition (e.g. source IP/VPC/MFA) and scope resources.",
                        "aws"))
                    break

        # Wildcard principal in resource policy = public exposure
        if principal in ("*", {"AWS": "*"}) or (
            isinstance(principal, dict) and principal.get("AWS") == "*"
        ):
            findings.append(Finding(
                "AWS009", Severity.CRITICAL, "Public principal (Principal:*)",
                f"Statement '{sid}' grants access to ANY AWS principal.",
                loc, "Set a specific account/role/ARN principal.", "aws"))

        # Allow with no condition and broad action set -> info nudge
        if not conditions and not wild_action and not wild_resource and actions:
            findings.append(Finding(
                "AWS010", Severity.INFO, "No Condition constraints",
                f"Statement '{sid}' has no Condition block; consider MFA/IP/time guards.",
                loc, "Add least-privilege Condition keys where practical.", "aws"))


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------
_GCP_PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}
_GCP_PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}


def _lint_gcp(doc: dict, findings: list[Finding]) -> None:
    bindings = _as_list(doc.get("bindings"))
    for i, b in enumerate(bindings):
        if not isinstance(b, dict):
            continue
        loc = f"$.bindings[{i}]"
        role = _norm(b.get("role", ""))
        members = [_norm(m) for m in _as_list(b.get("members"))]
        has_condition = bool(b.get("condition"))

        if role in _GCP_PRIMITIVE_ROLES:
            sev = Severity.CRITICAL if role == "roles/owner" else Severity.HIGH
            if role == "roles/viewer":
                sev = Severity.MEDIUM
            findings.append(Finding(
                "GCP001", sev, f"Primitive role bound ({b.get('role')})",
                f"Binding {i} uses broad primitive role '{b.get('role')}'.",
                loc, "Replace primitive roles with predefined/custom roles.",
                "gcp"))

        for m in members:
            short = m.split(":", 1)[-1] if ":" in m else m
            if short in _GCP_PUBLIC_MEMBERS or m in _GCP_PUBLIC_MEMBERS:
                findings.append(Finding(
                    "GCP002", Severity.CRITICAL, f"Public IAM member ({m})",
                    f"Binding {i} grants '{b.get('role')}' to the public.",
                    loc, "Remove allUsers/allAuthenticatedUsers bindings.",
                    "gcp"))

        for m in members:
            if m.startswith("serviceaccount:") and role == "roles/owner":
                findings.append(Finding(
                    "GCP003", Severity.HIGH,
                    "Service account with Owner role",
                    f"Binding {i} grants Owner to a service account ({m}).",
                    loc, "Grant the minimal predefined role to the SA.", "gcp"))

        if role.endswith("admin") and not has_condition:
            findings.append(Finding(
                "GCP004", Severity.MEDIUM,
                f"Admin role without IAM Condition ({b.get('role')})",
                f"Binding {i} grants an admin role with no condition.",
                loc, "Add an IAM Condition to constrain scope/time.", "gcp"))


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------
def _lint_azure(doc: dict, findings: list[Finding]) -> None:
    props = doc.get("Properties") if isinstance(doc.get("Properties"), dict) else doc
    permissions = _as_list(props.get("permissions") or props.get("Permissions"))
    scopes = _as_list(props.get("assignableScopes") or props.get("AssignableScopes"))
    role_name = props.get("roleName") or props.get("RoleName") or "role"

    # Flatten a single permissions object form if needed.
    if not permissions and ("actions" in props or "Actions" in props):
        permissions = [props]

    for i, perm in enumerate(permissions):
        if not isinstance(perm, dict):
            continue
        loc = f"$.Properties.permissions[{i}]"
        actions = [_norm(a) for a in _as_list(perm.get("actions") or perm.get("Actions"))]
        data_actions = [_norm(a) for a in _as_list(perm.get("dataActions") or perm.get("DataActions"))]
        not_actions = _as_list(perm.get("notActions") or perm.get("NotActions"))

        if "*" in actions:
            findings.append(Finding(
                "AZ001", Severity.CRITICAL, "Wildcard control-plane action (*)",
                f"Role '{role_name}' grants all management-plane actions.",
                loc, "Enumerate specific resource provider actions.", "azure"))
        if "*" in data_actions:
            findings.append(Finding(
                "AZ002", Severity.HIGH, "Wildcard data-plane action (*)",
                f"Role '{role_name}' grants all data-plane actions.",
                loc, "Scope dataActions to required operations.", "azure"))
        for a in actions:
            if a.endswith("/*") and a != "*":
                findings.append(Finding(
                    "AZ003", Severity.MEDIUM, f"Provider-wide wildcard ({a})",
                    f"Role '{role_name}' grants all actions under '{a}'.",
                    loc, "List individual operations rather than provider/*.",
                    "azure"))
        if not_actions and "*" in actions:
            findings.append(Finding(
                "AZ004", Severity.HIGH, "Wildcard actions with notActions denylist",
                f"Role '{role_name}' grants * minus a denylist (over-broad).",
                loc, "Use an explicit actions allowlist.", "azure"))

    for j, scope in enumerate(scopes):
        if str(scope).strip() == "/":
            findings.append(Finding(
                "AZ005", Severity.CRITICAL, "Root assignable scope (/)",
                f"Role '{role_name}' is assignable at tenant root '/'.",
                f"$.Properties.assignableScopes[{j}]",
                "Scope assignment to a subscription/resource group.", "azure"))


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def lint_policy(doc: Any, provider: str | None = None) -> list[Finding]:
    """Lint a single parsed policy document. Returns findings sorted by severity."""
    findings: list[Finding] = []
    prov = provider or detect_provider(doc)
    if not isinstance(doc, dict):
        findings.append(Finding(
            "GEN000", Severity.LOW, "Unrecognized policy shape",
            "Top-level document is not a JSON object.", "$",
            "Provide an AWS/GCP/Azure IAM policy JSON object.", prov))
        return findings

    if prov == "aws":
        _lint_aws(doc, findings)
    elif prov == "gcp":
        _lint_gcp(doc, findings)
    elif prov == "azure":
        _lint_azure(doc, findings)
    else:
        findings.append(Finding(
            "GEN001", Severity.LOW, "Unknown provider",
            "Could not detect AWS/GCP/Azure policy shape.", "$",
            "Use --provider to force a provider.", "unknown"))

    findings.sort(key=lambda f: Severity.rank(f.severity), reverse=True)
    return findings


def lint_document(text: str, provider: str | None = None) -> list[Finding]:
    """Parse JSON text and lint it."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        return [Finding(
            "GEN002", Severity.HIGH, "Invalid JSON",
            f"Could not parse policy: {exc}", "$",
            "Fix the JSON syntax.", provider or "unknown")]
    return lint_policy(doc, provider)


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0,
              Severity.LOW: 0, Severity.INFO: 0}
    total = 0
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        total += 1
    counts["TOTAL"] = total
    return counts
