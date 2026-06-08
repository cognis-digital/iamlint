# Demo 01 - Over-permissive AWS IAM policy

This scenario shows IAMLINT catching a classic least-privilege failure: an
IAM policy that was meant to let a deploy job touch one S3 bucket, but was
copy-pasted into a full administrative grant plus a `PassRole` escalation
path.

## Input

`overpermissive_policy.json` - an AWS identity policy with:

- `Action: "*"` on `Resource: "*"` (full admin)
- `iam:PassRole` on all resources (privilege escalation)
- `s3:*` service-wide wildcard
- a resource policy statement with `Principal: "*"` (public exposure)
- a sensitive `secretsmanager:GetSecretValue` grant with no Condition

## Run it

```sh
# Human-readable table (default)
python -m iamlint lint demos/01-basic/overpermissive_policy.json

# Machine-readable for CI pipelines
python -m iamlint lint demos/01-basic/overpermissive_policy.json --format json

# Self-contained shareable HTML report (the UI)
python -m iamlint lint demos/01-basic/overpermissive_policy.json \
    --format html -o report.html
```

## Expected outcome

IAMLINT exits non-zero and reports CRITICAL findings for the `*:*` admin
grant, the public principal, and unscoped `PassRole`, plus HIGH/MEDIUM
findings for the service wildcard and INFO nudges for missing Conditions.

The goal of the tool, in one line: **kill `*:*`.**
