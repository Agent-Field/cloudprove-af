# Open-Core Model

## Tier Structure

| | **Scan** (Free, OSS) | **Prove** (Free, OSS) | **Enterprise** (Commercial) |
|---|---|---|---|
| **License** | Apache 2.0 | Apache 2.0 | Commercial |
| **Input** | Repo URL / local path | Repo + cloud credentials | Managed SaaS or on-prem |
| **Static IaC analysis** | ✅ | ✅ | ✅ |
| **Resource graph reasoning** | ✅ | ✅ | ✅ |
| **Attack path construction** | ✅ (static only) | ✅ (static + live) | ✅ |
| **Live cloud verification** | ❌ | ✅ | ✅ |
| **Drift detection** | ❌ | ✅ | ✅ |
| **Blast radius calculation** | ❌ | ✅ | ✅ |
| **SARIF output** | ✅ | ✅ | ✅ |
| **Compliance frameworks** | CIS AWS only | CIS AWS/GCP/Azure, SOC2, HIPAA | All frameworks + custom |
| **Multi-account scanning** | ❌ | ❌ | ✅ |
| **Org-wide policy engine** | ❌ | ❌ | ✅ |
| **Scheduled continuous monitoring** | ❌ | ❌ | ✅ |
| **RBAC + audit trail** | ❌ | ❌ | ✅ |
| **SSO / SAML** | ❌ | ❌ | ✅ |
| **SLA + support** | Community only | Community only | ✅ |
| **Cost** | LLM API costs only | LLM API costs only | Contact sales |

## Why Both Scan and Prove Are Free

The Bridgecrew playbook: Checkov (the OSS scanner) was always free. The commercial offering (Bridgecrew platform) added org management, continuous monitoring, and policy-as-code. Palo Alto acquired them for ~$200M primarily because of Checkov's developer adoption.

We follow the same model:
1. **Both scan and prove are Apache 2.0** — maximizes adoption, maximizes AgentField downloads
2. **Enterprise adds org-level features** — things individual developers don't need but security teams require
3. **The value ladder**: scan (try it) → prove (love it) → enterprise (need it for compliance)

## What Enterprise Adds (Not in OSS)

Enterprise features are things that don't make sense for individual developers but are required for organizations:

1. **Multi-account scanning** — scan all AWS accounts in an org from one place
2. **Org-wide policy engine** — define custom security policies that apply across all repos
3. **Scheduled continuous monitoring** — nightly scans with drift alerting
4. **RBAC + audit trail** — who ran what scan, who approved which exception
5. **SSO / SAML** — enterprise identity integration
6. **Custom compliance frameworks** — define org-specific controls
7. **API rate limits** — higher concurrency for large-scale scanning
8. **SLA + dedicated support**

These are all orchestration/management features. The core intelligence (harnesses, scoring, SARIF) remains fully open source.

## Revenue Model

| Source | When | Amount |
|---|---|---|
| **LLM API costs** | Always (user pays their own OpenRouter/Anthropic key) | $0 to us |
| **Enterprise license** | Orgs with 10+ repos, compliance requirements | $X,000/yr |
| **Managed SaaS** | Teams that don't want to self-host AgentField | $X/scan or $X/mo |
| **Acquisition** | When adoption hits critical mass (10k+ GitHub stars) | $XXM |

## Acquisition Attractiveness Checklist

Following the patterns from Bridgecrew ($200M by Palo Alto), Lacework ($200M by Fortinet), Bionic ($350M by CrowdStrike):

- [x] Open source with strong developer adoption (GitHub stars, PyPI downloads)
- [x] CI/CD integration (runs on every PR — daily active usage)
- [x] Unique technical differentiation (AI-native, not rule-based)
- [x] Cloud-native focus (AWS, GCP, Azure — the growth market)
- [x] Compliance framework mapping (CIS, SOC2, HIPAA, PCI-DSS)
- [x] SARIF output (integrates with acquirer's existing security platform)
- [x] Low customer acquisition cost (developers adopt for free, enterprise upsell)
- [ ] 10,000+ GitHub stars
- [ ] 50,000+ monthly PyPI downloads (each = AgentField download)
- [ ] 100+ enterprise customers
