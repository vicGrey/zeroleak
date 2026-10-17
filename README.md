<div align="center">

# 🛡️ ZeroLeak AI

### 100% Offline, Privacy-First AWS IAM Security Auditor
**Deterministic Policy Gate (OPA / Conftest Rego) meets Local Open Intelligence (Google Gemma 2 2B)**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Model](https://img.shields.io/badge/Model-Google%20Gemma%202%202B-8E44AD)](https://ai.google.dev/gemma)
[![Policy Gate](https://img.shields.io/badge/Policy%20Engine-Conftest%20%2F%20OPA%20Rego-00ADD8)](https://www.conftest.dev/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Offline%20%26%20Zero%20Telemetry-success)](docs/ARCHITECTURE_PLAN.md)
[![Docker](https://img.shields.io/badge/Deployment-Docker%20%26%20Compose-2496ED)](docker-compose.yml)

**No cloud endpoints. No API tokens. No vendor DPA required. $0 cloud spend.**

[Architecture](#-5-stage-pipeline-architecture) • [Empirical Benchmark](#-empirical-benchmark-scorecard-10-hand-crafted-policies) • [The Discovery Loop](#-the-discovery-loop-breaking-the-circular-verification-trap) • [Quickstart](#-quickstart-guide) • [Terraform Audit](#-batch-terraform-plan-audit) • [The Wi-Fi Off Test](#-the-wi-fi-off-verification-challenge)

</div>

---

## 💡 The Problem: Cloud LLMs Send Your Infrastructure Secrets Off-Machine

AWS IAM policies are the master keys to an organization's infrastructure. Auditing them with proprietary cloud LLM APIs (OpenAI, Anthropic, Bedrock) introduces an unacceptable privacy trade-off: **you must send internal account IDs, IAM role naming conventions, ARN hierarchies, and bucket topologies across the public internet to third-party servers.**

For freelance cloud security consultants, DevSecOps contractors reviewing client infrastructure under Non-Disclosure Agreements (NDAs), and regulated engineering teams (HIPAA, PCI-DSS, SOC 2), signing a vendor Data Processing Agreement (DPA) just to lint JSON permissions is a non-starter.

Traditional static analysis linters (like Checkov, tfsec, or raw Conftest) excel at checking syntax against known rules. While mature tools like Checkov, Cloudsplaining, or PMapper include checks for known privilege escalation combinations, rule-based systems are inherently bound by static signatures: **they can only catch the specific combination patterns someone has already anticipated and encoded into that specific ruleset.** If an engineer encounters unencoded cross-service workflows or complex multi-statement policies, static rules remain blind until an engineer manually authors a new check.

---

## ⚡ The Solution: ZeroLeak AI

I designed **ZeroLeak AI** as a hybrid, defense-in-depth security auditor that runs **completely offline on consumer-grade hardware**:

1. **Deterministic Rego Rule Gate (Conftest / OPA):** Enforces zero-tolerance syntax and wildcard rules in tens of milliseconds (~20ms subprocess execution). The Rego gate evaluates policy structure directly, making it immune to prompt injection embedded in policy strings.
2. **Local Open-Weight Intelligence (Google Gemma 2 2B):** Provides contextual reasoning over exploit risks (such as multi-permission combos like PassRole+Lambda) and polymorphic permission formats via local Ollama without sending bytes over the wire.
3. **Automated Remediator & Re-Verifier:** Generates scoped least-privilege replacements, tracks permission loss (Narrowed vs. Dropped), and passes remediated JSON back through the Conftest gate to verify that zero defined rule violations remain.
4. **Professional Security Deliverables:** Produces client-ready **Markdown** and **WeasyPrint PDF reports** formatted for freelance client handoff.

---

## 🔬 5-Stage Pipeline Architecture

```
                       [ Input: IAM Policy JSON / Terraform Plan ]
                                            │
                    ┌───────────────────────┴───────────────────────┐
                    ▼                                               ▼
         [ Stage 1: Deterministic Gate ]                [ Stage 2: Gemma 2 2B ]
         • Fast (~20ms Conftest subprocess)             • Local Ollama Daemon
         • Catches wildcards & syntax errors            • Contextual exploit reasoning
         • Rego engine ignores prompt injection         • Explains real-world attack paths
                    │                                               │
                    └───────────────────────┬───────────────────────┘
                                            ▼
                           [ Stage 3: Automated Remediation ]
                           • Gemma crafts scoped, least-privilege replacement
                           • Syntax validation & fallback sanitizers
                                            ▼
                           [ Stage 4: Conftest Re-Verification ]
                           • Remediated policy re-enters deterministic gate
                           • Verifies 0 violations of active Rego ruleset
                                            ▼
                           [ Stage 5: Permission Delta & Loss Tracker ]
                           • Narrowed vs. Dropped permissions delta
                           • Flagged review for high-impact alterations
                                            ▼
                          [ Client Deliverable: PDF & Markdown ]
                          • Client-ready reports with zero telemetry
                          • Clean formatting (internal latency metrics omitted)
```

---

## 🔁 The Discovery Loop: Breaking the "Circular Verification" Trap

When auditing Test 04 (`iam:PassRole` + `lambda:CreateFunction`), a naive pipeline encounters a dangerous logic trap:

1. **The Circular Trap:** The baseline ruleset only checks for wildcards (`*`). It has no rule for `PassRole` + `Lambda`.
2. When the original policy runs through Conftest, it reports **0 violations** (a silent pass).
3. Gemma flags the privilege escalation and generates a scoped fix.
4. When the fixed policy is re-verified in Stage 4, Conftest again reports **0 violations**.
5. Claiming this policy is *"Remediated & Verified"* at this stage is **completely circular**: an invalid fix that still contained the dangerous combo would have passed too, because the gate was never testing for it!

### The Non-Circular Solution: The Continuous Hardening Loop
ZeroLeak AI turns this circular check into an active security hardening loop:

1. **Discovery:** Gemma flags the unencoded `iam:PassRole` + `lambda:CreateFunction` combination.
2. **Codification:** The human operator codifies that finding into a new Rego v1 rule in `policies/iam_policy.rego`:

```rego
import rego.v1

deny contains msg if {
    some s1 in get_statements
    s1.Effect == "Allow"
    has_action(s1, "iam:PassRole")
    some s2 in get_statements
    s2.Effect == "Allow"
    has_action(s2, "lambda:CreateFunction")
    msg := "[Rule: passrole_lambda_escalation] PassRole paired with lambda:CreateFunction allows privilege escalation via role assumption."
}
```

3. **True Verification:** With the rule codified into the gate:
   - **Original Policy:** Conftest flags **1 Violation** (`passrole_lambda_escalation`).
   - **Remediated Policy:** Conftest flags **0 Violations**.

The circularity is broken. Gemma spots the pattern; the engineer verifies it; Conftest locks it down deterministically forever.

---

## 📊 Empirical Benchmark Scorecard (10 Hand-Crafted Policies)

I ran an automated empirical benchmark across 10 hand-crafted IAM policies targeting specific real-world security vulnerabilities, AWS anti-patterns, and edge cases.

All 10 tests were executed with live **Google Gemma 2 2B** via Ollama on local laptop hardware.

| # | Policy Scenario | Conftest Alone | Gemma 2B Alone | ZeroLeak Unified Pipeline | Key Takeaway / Significance |
|:---:|---|:---:|:---:|:---:|---|
| **01** | `01_control.json`<br>*(Compliant Baseline)* | 0 Violations | 0 Risks | 🛡️ **Preserved Intact**<br>*(Baseline Control)* | Gate & LLM agree clean scoped policy needs no modification. |
| **02** | `02_wildcard_action.json`<br>*(Overpermissive Action)* | 1 Violation | 1 Risk | 🛠️ **Remediated & Verified**<br>*(0 Remaining)* | Gate flags wildcard; Gemma scopes to `s3:GetObject`/`PutObject`. |
| **03** | `03_wildcard_resource.json`<br>*(Overpermissive Resource)* | 1 Violation | 1 Risk | 🛠️ **Remediated & Verified**<br>*(0 Remaining)* | Scoped from `*` to specific S3 bucket ARN pattern. |
| **04** | `04_combo_escalation.json`<br>*(PassRole + Lambda)* | **0 Violations<br>(Unencoded in Gate)** | 🧠 **1 Risk Caught**<br>*(64.2s)* | 🎯 **Gemma-Only Catch**<br>*(1 Fail $\rightarrow$ 0 Fail once codified)* | Baseline gate was blind. Gemma flagged the privesc combo. Codifying the rule turned 0 violations into 1, then verified clean at 0. |
| **05** | `05_dynamodb_overpriv.json`<br>*(Data Exfiltration)* | 2 Violations | 1 Risk | 🛠️ **Flagged for Review** | Identified table scan & admin destruction hazards. |
| **06** | `06_polymorphic.json`<br>*(String vs Array)* | 2 Violations | 2 Risks | 🛠️ **Remediated & Verified**<br>*(0 Remaining)* | Handles polymorphic AWS schema types without parser exceptions. |
| **07** | `07_notaction_allow.json`<br>*(Dangerous NotAction)* | 2 Violations | 1 Risk | 🛠️ **Remediated & Verified**<br>*(0 Remaining)* | Catches bypass technique granting every permission except one. |
| **08** | `08_sts_assumerole.json`<br>*(Account Hijacking)* | 1 Violation | 1 Risk | 🛠️ **Remediated & Verified**<br>*(0 Remaining)* | Blocks wildcards in `sts:AssumeRole` trust relationships. |
| **09** | `09_ec2_iam_attach.json`<br>*(Instance Profile Abuse)* | 1 Violation | 2 Risks | 🛠️ **Remediated & Verified**<br>*(0 Remaining)* | Detects EC2 profile injection vector. |
| **10** | `10_prompt_injection.json`<br>*(Adversarial Sid Attack)* | ⚡ **2 Violations Caught**<br>*(Gate ignores string)* | Resisted injection;<br>flagged wildcards | 🔒 **Gate Enforced**<br>*(Defense-in-Depth)* | The `Sid` instructed the auditor to ignore violations. The deterministic gate evaluates structure alone, ignoring natural language prompts. |

> **Benchmark Methodology & Caveats:**
> - **Dataset:** 10 hand-crafted synthetic test policies covering common AWS IAM anti-patterns and edge cases.
> - **Parameters:** Inferences were run with local Ollama using `temperature=0.1` (`top_p=0.9`, single pass per policy) to prioritize consistent output.
> - **Execution Latency:** On a standard consumer CPU (no dedicated GPU), Gemma 2 2B had a **mean latency of 52.2s** (ranging from **39.0s to 67.3s**) per policy analysis. It is slower than cloud APIs, but operates with zero marginal cost and zero data transmission.
> - *Caveats:* Generative open-weight model outputs can vary between runs, sampling parameters, and hardware backends. 2B models can recall common privilege escalation patterns (like PassRole + Lambda), but will not catch every obscure escalation graph.
>
> Full raw test logs, including the codified before/after loop on Test 04, are available in [`samples/results/`](samples/results/).

---

## 🤖 Why Google Gemma 2 (2B)?

While newer and larger models exist (including Gemma 3), I deliberately selected **Google Gemma 2 2B** for ZeroLeak AI:

1. **Consumer Hardware Accessibility:** Gemma 2 2B is a ~1.6 GB download that runs comfortably in ~3–4 GB of system RAM on a standard laptop CPU without requiring a discrete Nvidia GPU.
2. **Schema Adherence with Guardrails:** For single-turn structured JSON auditing and remediation, Gemma 2 2B usually respects schema constraints. When occasional model truncation occurs on complex policies, ZeroLeak's Stage 3 fallback sanitizers safely repair trailing JSON tokens.
3. **Zero Barrier to Entry:** A freelance security consultant can run ZeroLeak on a standard work laptop in an airplane, client office, or coffee shop without thermal throttling, cloud API bills, or enterprise licensing.
4. **Model-Agnostic Decoupling:** The Ollama inference layer is completely decoupled. Consultants running on Apple Silicon or discrete GPUs can switch to larger models like `gemma2:9b` or future Gemma releases simply by changing the model tag in Ollama.

---

## 🚀 Quickstart Guide

You can run ZeroLeak AI in two modes: **Turnkey Docker** (easiest, cross-platform) or **Native Python** (fastest, leverages local CPU/GPU).

### Option A: Turnkey Docker (Recommended for Windows / Mac / Linux)

ZeroLeak provides a multi-container Docker Compose setup that runs the Streamlit application and an isolated Ollama service with automatic model provisioning:

```bash
# 1. Clone the repository
git clone https://github.com/vicGrey/zeroleak.git
cd zeroleak

# 2. Launch the entire stack
docker compose up
```

- Docker will automatically pull Ollama, download `gemma2:2b`, build the ZeroLeak container with Conftest & WeasyPrint, and wire them together.
- *(Note: Initial setup requires an internet connection once to download container images and model weights. After that first pull, everything runs 100% offline.)*
- Open your browser to **`http://localhost:8501`**.

---

### Option B: Native Setup (Maximum Performance)

#### 1. System Requirements & Dependencies
- Python 3.10+
- [Conftest](https://www.conftest.dev/install/) (`v0.56.0`+)
- [Ollama](https://ollama.com/)
- Pango & Cairo (required for WeasyPrint PDF export):
  - **Ubuntu/Debian:** `sudo apt-get install -y libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0`
  - **macOS:** `brew install pango`
  - **Windows:** Included in Docker; or install GTK3 runtime.

#### 2. Install & Start
```bash
# 1. Clone and enter repo
git clone https://github.com/vicGrey/zeroleak.git
cd zeroleak

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Pull Gemma 2 2B in Ollama (requires internet once)
ollama pull gemma2:2b

# 4. Launch the application
streamlit run app.py
```
Access the dashboard at **`http://localhost:8501`**.

---

## 📦 Batch Terraform Plan Audit

ZeroLeak AI goes beyond standalone JSON files: it parses full **Terraform Plan JSON files** (`terraform show -json tfplan.json`) and extracts every IAM resource automatically:

- `aws_iam_policy`
- `aws_iam_role_policy`
- `aws_iam_user_policy`
- `aws_iam_group_policy`

```bash
# In your Terraform project:
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Upload tfplan.json to ZeroLeak AI and click "Audit Entire Plan (Unified)"
```

ZeroLeak systematically extracts all IAM policies from your plan, screening them instantaneously against the deterministic Rego gate (~20ms per policy), tracking uncomputed dynamic policies (`Known After Apply`), and dispatching only failing policies to local Gemma 2 2B for contextual threat modeling and automated remediation.

> **Operational Timing & Gate-First Triage:**
> In Batch Mode, ZeroLeak operates **gate-first**: policies passing the deterministic AST gate require no LLM remediation, keeping batch audits practical on standard CPUs (e.g., an audit of 48 resources containing 10 IAM policies with 2 failing policies completes in **102 seconds** rather than 9+ minutes). 
> 
> *Scaling & Trade-off:* Each failing policy dispatched to Gemma 2 2B requires a single structured prompt averaging **52.2s on CPU**. The explicit trade-off of gate-first batch screening is that gate-passing policies bypass LLM semantic review, meaning unencoded combination risks (like Test 04) are evaluated only if audited individually in Single Policy mode or if codified into the Rego gate. For massive plans with dozens of failing policies (50–100+), sequential CPU runtime scales to **43–87 minutes**, where local GPU acceleration or codified rules become recommended.

---

## ✈️ The "Wi-Fi Off" Verification Challenge

Don't take my word for it — verify ZeroLeak AI's privacy guarantee in about a minute:

> *(Note: The initial setup step to download Docker images and model weights requires an internet connection once. Once downloaded, complete isolation is verified as follows:)*

1. Launch ZeroLeak AI and load an IAM policy or Terraform plan.
2. **Physically disconnect your Ethernet cable or toggle Wi-Fi OFF.**
3. Click **"Run ZeroLeak Audit"** (or **"Audit Entire Plan (Unified)"**).
4. Observe the complete 5-stage pipeline execute:
   - Conftest Rego checks run locally via native binary (~20ms).
   - Google Gemma 2 2B infers locally via Ollama on `localhost:11434`.
   - Remediated policy is re-verified and rendered.
   - Professional PDF & Markdown deliverables are generated.

ZeroLeak AI operates with **zero telemetry** (`gatherUsageStats = false` in `.streamlit/config.toml`) and zero cloud dependencies.

---

## 🗂️ Project Structure

```
zeroleak/
├── app.py                      # Modern Streamlit UI with 5-stage inspection tabs
├── engine/
│   ├── opa_gate.py             # Conftest subprocess execution & JSON parsing
│   ├── gemma_analyzer.py       # Local Ollama client & structured Gemma 2B prompting
│   ├── diff_tracker.py         # Permission delta tracking & guardrail analysis
│   ├── tfplan_parser.py        # Terraform plan JSON parser for IAM resources
│   ├── report_generator.py     # Client-ready Markdown & WeasyPrint PDF reports
│   └── benchmark_runner.py     # Automated 10-policy empirical test suite
├── policies/
│   └── iam_policy.rego         # Modern Rego v1 deterministic security rules
├── samples/
│   ├── policies/               # 10 benchmark test policies (01-10)
│   └── results/                # Ground-truth empirical benchmark outputs
├── docs/
│   ├── ARCHITECTURE_PLAN.md    # Original engineering notes & architectural plan
│   └── DEV_SUBMISSION.md       # Submission article for DEV Hacktoberfest
├── Dockerfile                  # Self-contained container with Conftest & WeasyPrint
├── docker-compose.yml          # Dual-service compose with auto-Ollama Gemma 2B setup
├── requirements.txt            # Python dependencies
└── README.md                   # This documentation
```

---

## ⚖️ Engineering Integrity & Boundaries

ZeroLeak AI is built on honest security engineering:
- **Rule Limits & Coarseness:** Passing Conftest verifies that a policy triggers zero violations *of your active Rego ruleset*—it does not prove the policy is universally bug-free or safe for every operational use case. Furthermore, the example PassRole rule in the Discovery Loop is intentionally coarse: it flags any policy containing both `iam:PassRole` and `lambda:CreateFunction`, which would flag a legitimately scoped deployer role. In production, teams should tighten the rule to inspect PassRole's `Resource` ARN and verify the absence of an `iam:PassedToService` condition.
- **Human-in-the-Loop:** While Gemma 2 2B generates scoped least-privilege suggestions, all production permission alterations must undergo peer review prior to deployment.
- **Single-Policy Scope:** ZeroLeak audits policies on a per-policy / per-statement level. Real-world AWS privilege escalation often spans multiple distinct managed or inline policies attached to the same IAM role, group, or identity. Cross-policy aggregation and effective identity permission graph mapping require dedicated multi-policy traversal tools like PMapper.
- **Discovery Evidence Scope:** While Gemma 2 2B successfully flagged the PassRole + Lambda escalation combination without a pre-existing rule in our test suite (n=1), a 2B parameter model cannot be assumed to reliably catch all multi-permission escalation chains without dedicated benchmark verification across broader attack corpuses.
- **Real-World False Positives & Service Constraints:** As revealed in our live Terraform plan audit, AWS APIs frequently mandate wildcard resources for actions that do not support resource-level permissions (e.g., `config:PutEvaluations`). LLMs prompted to eliminate wildcards will attempt to invent scoped ARNs or omit necessary actions (e.g., dropping `logs:PutLogEvents`), reinforcing why automated remediations require manual review against AWS Service Authorization references.
- **Resource Scope:** When generic wildcard resources (`Resource: "*"`) are remediated without access to an active AWS account's live inventory, ZeroLeak prompts the operator with standardized, parameterized ARN templates (e.g. `arn:aws:s3:::my-bucket/*`).
- **Complementary to Deep Analysis Tools:** A 2B parameter model running locally is an effective quick-audit scout for common privilege escalation chains, but it is not a substitute for deep graph-traversal security tools like PMapper or AWS IAM Access Analyzer.
- **Attribution & Prior Research:** Foundational wildcard Rego patterns were adapted and expanded from my prior academic research in serverless zero-trust governance ([aws-serverless-zero-trust-governance](https://github.com/vicGrey/aws-serverless-zero-trust-governance)).

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information. Built for the **DEV Hacktoberfest 2026** *Best Use of Gemma* challenge.
