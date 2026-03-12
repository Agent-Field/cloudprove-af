<div align="center">

# CloudProve-AF

### AI-Native Cloud Infrastructure Security Scanner Built on [AgentField](https://github.com/Agent-Field/agentfield)

[![Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-16a34a?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Built with AgentField](https://img.shields.io/badge/Built%20with-AgentField-0A66C2?style=for-the-badge)](https://github.com/Agent-Field/agentfield)
[![More from Agent-Field](https://img.shields.io/badge/More_from-Agent--Field-111827?style=for-the-badge&logo=github)](https://github.com/Agent-Field)

<p>
  <a href="#what-you-get-back">Output</a> •
  <a href="#why-cloudprove">Why CloudProve</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="docs/ARCHITECTURE.md">Full Spec</a>
</p>

</div>

Other tools match patterns against a rule database. CloudProve **constructs multi-resource attack paths and proves exploitability**: every finding ships with a step-by-step attack narrative, adversarial verification, and an IaC fix. Free, open source, one API call. A full scan of a Terraform repo costs about **$0.50 in LLM calls**.

<p align="center">
  <img src="assets/hero.png" alt="CloudProve-AF — shift-left attack path analysis" width="100%" />
</p>

## Why CloudProve?

Checkov, tfsec, and KICS find individual misconfigurations. Wiz and Orca construct attack paths — but require your infrastructure **deployed**. CloudProve fills the gap: **attack path analysis from IaC alone**, before you deploy.

| Capability | CloudProve-AF | Checkov / tfsec / KICS | Wiz / Orca |
|---|---|---|---|
| **Approach** | AI reasoning over resource graph | ~3,000 static rules | Graph-based, live cloud |
| **Attack path chains** | Yes (CHAIN phase) | No (individual findings) | Yes |
| **Requires deployment** | **No** — IaC only | No — IaC only | **Yes** — live cloud |
| **Adversarial verification** | HUNT → PROVE (near-zero false positives) | Pattern match (high noise) | Runtime checks |
| **IaC remediation** | Fix diffs + breaking change analysis | Basic fix hints | N/A (runtime tool) |
| **Cost** | **Free / open source** (BYOK) | Free / open source | Enterprise ($$$) |

## Architecture

<p align="center">
  <img src="assets/architecture.png" alt="CloudProve-AF Signal Cascade Pipeline" width="100%" />
</p>

- **RECON**: Reads IaC, builds a resource graph, and optionally pulls live cloud state and drift.
- **HUNT**: Runs 7 parallel domain hunters (IAM, network, data, secrets, compute, logging, compliance).
- **CHAIN**: Combines individual findings into multi-step attack paths across resources.
- **PROVE**: Adversarial verification — tries to disprove each path. Near-zero false positives.
- **REMEDIATE**: Generates IaC fix diffs and evaluates breaking change / downtime impact.

> Full architecture deep-dive: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Quick Start

```bash
pip install cloudprove-af

# Start AgentField control plane
# (typically at http://localhost:8080)

cloudprove-af  # starts on port 8004

# Trigger a scan
curl -X POST http://localhost:8004/api/v1/execute/async/cloudprove.scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/org/infra-repo"}'
```

Key API skills:
- `cloudprove.scan` (Tier 1 static analysis)
- `cloudprove.prove` (Tier 2+ live verification flow)

## Three Tiers

| Tier | Input | Capability |
|---|---|---|
| **Tier 1 (No Credentials)** | `repo_url` | Static IaC analysis, resource graph construction, attack path discovery, and IaC remediation generation |
| **Tier 2 (Read-Only Credentials)** | `repo_url` + cloud config | Tier 1 plus live verification and drift detection |
| **Tier 3 (Deep Mode)** | Cloud credentials (repo optional) | Tier 2 plus full graph traversal, cross-account analysis, and deeper IAM simulation workflows |

## CI/CD Integration

CloudProve is designed for PR-time scanning with SARIF upload:

```yaml
name: cloudprove-scan
on:
  pull_request:
    paths:
      - '**/*.tf'
      - '**/*.yaml'
      - '**/*.yml'

jobs:
  infrastructure-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Trigger CloudProve
        run: |
          curl -sS -X POST "$AGENTFIELD_SERVER/api/v1/execute/async/cloudprove.scan" \
            -H "Content-Type: application/json" \
            -d '{"input":{"repo_url":".","depth":"quick","output_formats":["sarif","json"]}}'
```

See [`docs/GITHUB_ACTIONS.md`](docs/GITHUB_ACTIONS.md) for full Tier 1 and Tier 2 workflows.

## Output Formats

- `sarif`: SARIF 2.1.0 for GitHub code scanning and security platforms
- `json`: Full structured output for pipelines and APIs
- `markdown`: Human-readable report for platform/security reviews

## Configuration

### Key Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTFIELD_SERVER` | No | `http://localhost:8080` | AgentField control plane URL |
| `NODE_ID` | No | `cloudprove` | Agent node identifier |
| `OPENROUTER_API_KEY` | Yes | - | Model provider credential |
| `CLOUDPROVE_PROVIDER` | No | `opencode` | Harness provider override |
| `CLOUDPROVE_MODEL` | No | `minimax/minimax-m2.5` | Harness model |
| `CLOUDPROVE_AI_MODEL` | No | `CLOUDPROVE_MODEL`/`AI_MODEL` fallback | `.ai()` gate model |
| `CLOUDPROVE_MAX_TURNS` | No | `50` | Max turns per harness call |
| `CLOUDPROVE_REPO_PATH` | No | cwd | Local repository path fallback |
| `AGENT_CALLBACK_URL` | No | `http://127.0.0.1:8004` | Agent callback endpoint |

### Core `CloudProveInput` Fields

- `repo_url`, `branch`, `commit_sha`, `base_commit_sha`
- `depth` (`quick` | `standard` | `thorough`)
- `severity_threshold` (`critical` | `high` | `medium` | `low` | `info`)
- `output_formats` (`sarif` | `json` | `markdown`)
- `compliance_frameworks` (for example: `cis_aws`, `soc2`, `hipaa`, `pci_dss`)
- `cloud` (`provider`, `regions`, `account_id`, `assume_role_arn`) for Tier 2+
- Budget controls: `max_cost_usd`, `max_duration_seconds`, `max_concurrent_hunters`, `max_concurrent_provers`
- Scope filters: `include_paths`, `exclude_paths`
- CI fields: `is_pr`, `pr_id`, `fail_on_findings`

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]

pytest
ruff check src tests
mypy src

# Run service locally
cloudprove-af
```

Package metadata:
- Python: `>=3.11`
- License: Apache-2.0
- Core deps: `agentfield`, `pydantic>=2.0`, `pyhcl2>=4.0`

## Open Core Model

CloudProve uses an open-core model: `scan` and `prove` remain open source (Apache 2.0), while enterprise adds org-scale controls such as multi-account management, scheduled monitoring, and RBAC/audit features. See [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md) for the full tier breakdown.

## License

CloudProve-AF is licensed under Apache 2.0. See [`LICENSE`](LICENSE).
