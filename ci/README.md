# JGD CI/CD integration templates

JGD owns the deserialization domain logic. CI systems only supply the target,
authorization/policy, baseline, and budget; they consume JSON/SARIF findings.

## Entry points

| Pipeline | File | Notes |
|---|---|---|
| GitHub Actions | `ci/github-actions.yml` + root `action.yml` | SARIF upload and job gate |
| GitLab CI | `ci/gitlab-ci.yml` | SARIF artifact report, failing job on gate |
| Jenkins | `ci/Jenkinsfile` | archive + optional SARIF plugin |
| pre-commit | `ci/pre-commit`, `.pre-commit-hooks.yaml` | local left-shift hook |
| Nexus webhook | `jgd serve webhook` | repository event receiver |

## Gate semantics

`jgd audit` writes `gate.json` and exits:

- `0` — no finding at or above `--fail-on`
- `10` — gate failed
- `20` — tool/policy failure
- `30` — bad target/configuration
- `40` — internal error

Use `--baseline prior-run.json` to fail only on **new** findings. Existing
findings remain in the report but are not blocking.

## Nexus webhook

Nexus Repository Manager can call a webhook on component/asset creation.
Run the receiver on the private network:

```bash
export JGD_WEBHOOK_TOKEN='replace-me'
jgd serve webhook \
  --host 0.0.0.0 --port 8090 \
  --token "$JGD_WEBHOOK_TOKEN" \
  --secret "$JGD_WEBHOOK_SECRET" \
  --nexus-base-url https://nexus.example.com/repository/maven-releases \
  --nexus-token "$NEXUS_READ_TOKEN" \
  --profile standard --fail-on high
```

Configure the Nexus webhook URL as:

```text
http://jgd-webhook.internal:8090/webhooks/nexus
```

Accepted payload shapes include the common fields:

```json
{
  "action": "CREATED",
  "asset": {
    "downloadUrl": "https://nexus.example.com/repository/maven-releases/com/acme/demo/1.0/demo-1.0.jar",
    "path": "com/acme/demo/1.0/demo-1.0.jar"
  }
}
```

Security defaults:

- token and/or HMAC secret is mandatory;
- only `.jar` artifacts are accepted;
- URL downloads must stay under `--nexus-base-url` (scheme/host/path prefix);
- local paths must stay under `--local-root`;
- 512 MB artifact limit;
- bind to loopback unless deliberately exposed on a private network.

For a pull-based alternative, use the CLI or MCP adapter instead of opening a
webhook port.

## Baseline generation

```bash
# First run: establish the legacy baseline.
jgd audit --target build/libs --profile standard --out .jgd/baseline

# PR run: fail only on new findings.
jgd audit --target build/libs --profile standard \
  --baseline .jgd/baseline/run.json --fail-on high --out jgd-report
```

## Artifacts

Every run writes:

- `run.json` — full result and coverage
- `findings.json` — findings array
- `report.sarif` — SARIF 2.1.0
- `report.md` — human summary
- `gate.json` — deterministic gate decision
