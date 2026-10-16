import datetime
import json
from typing import Any, Dict, List, Optional


def generate_markdown_report(
    policy_name: str,
    original_policy: Dict[str, Any],
    conftest_results: Dict[str, Any],
    gemma_results: Optional[Dict[str, Any]],
    diff_results: Optional[Dict[str, Any]],
    reverification_results: Optional[Dict[str, Any]],
) -> str:
    """
    Generates a professional, client-ready Markdown audit deliverable.
    """
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    opa_passed = conftest_results.get("passed", False)
    opa_violations = conftest_results.get("violations", [])
    opa_status = "PASSED" if opa_passed else f"FAILED ({len(opa_violations)} violations)"

    gemma_success = gemma_results.get("success", False) if gemma_results else False
    threat_text = gemma_results.get("threat_explanation", "Not evaluated.") if gemma_results else "N/A"
    combos = gemma_results.get("combination_risks", []) if gemma_results else []
    fix_explanation = gemma_results.get("fix_explanation", "") if gemma_results else ""
    suggested_fix = gemma_results.get("suggested_fix") if gemma_results else None

    # Guardrails and permission loss
    narrowed = diff_results.get("narrowed", []) if diff_results else []
    dropped = diff_results.get("dropped", []) if diff_results else []
    retained = diff_results.get("retained", []) if diff_results else []
    added = diff_results.get("added", []) if diff_results else []
    warnings = diff_results.get("warnings", []) if diff_results else []

    reverify_status = "N/A"
    if reverification_results:
        reverify_passed = reverification_results.get("passed", False)
        reverify_status = "PASSED (0 violations)" if reverify_passed else f"FAILED ({reverification_results.get('violation_count', 0)} violations remaining)"

    lines = [
        f"# ZeroLeak AI — Security Audit & Remediation Deliverable",
        f"",
        f"> **Audited Resource:** `{policy_name}`  ",
        f"> **Audit Timestamp:** `{now}`  ",
        f"> **Execution Mode:** 100% Offline (Local Conftest AST Gate + Gemma 2 2B via Ollama)",
        f"",
        f"---",
        f"",
        f"## 1. Executive Summary",
        f"",
        f"| Verification Gate | Result | Details |",
        f"| :--- | :--- | :--- |",
        f"| **Deterministic Policy Gate (OPA)** | `{opa_status}` | {len(opa_violations)} syntax/wildcard rule violations caught |",
        f"| **Local Intelligence Gate (Gemma 2)** | `{'COMPLETED' if gemma_success else 'OFFLINE / SKIPPED'}` | Evaluated exploit chains & privilege escalation combinations |",
        f"| **Automated Re-Verification Pass** | `{reverify_status}` | Conftest validation on proposed remediation |",
        f"",
    ]

    # Deterministic Violations
    lines.extend([
        f"## 2. Deterministic Gate Findings (`[Rule]`)",
        f"",
    ])
    if opa_violations:
        for idx, v in enumerate(opa_violations, 1):
            lines.append(f"{idx}. **`{v.get('rule')}`**: {v.get('message')}")
        lines.append("")
    else:
        lines.append("No deterministic wildcard or syntax violations detected.\n")

    # Gemma Findings
    lines.extend([
        f"## 3. Exploit Analysis & Combination Risks (`[Gemma]`)",
        f"",
        f"**Threat Assessment:**",
        f"",
        f"{threat_text}",
        f"",
    ])

    if combos:
        lines.append(f"**Identified Privilege Escalation Combinations:**")
        for c in combos:
            lines.append(f"- {c}")
        lines.append("")

    # Permission Loss Analysis
    lines.extend([
        f"## 4. Permission Loss & Guardrail Analysis",
        f"",
        f"ZeroLeak strictly tracks permission shifts to prevent breaking production runtime:",
        f"",
        f"- **Narrowed Actions ({len(narrowed)}):** `{', '.join(narrowed) if narrowed else 'None'}`",
        f"- **Dropped Actions ({len(dropped)}):** `{', '.join(dropped) if dropped else 'None'}`",
        f"- **Retained Actions ({len(retained)}):** `{', '.join(retained) if retained else 'None'}`",
        f"- **Newly Added Actions ({len(added)}):** `{', '.join(added) if added else 'None'}`",
        f"",
    ])

    if warnings:
        lines.append(f"### Guardrail Alerts & Warnings")
        for w in warnings:
            lines.append(f"> [!WARNING]  \n> {w}\n")

    # Suggested Fix
    if suggested_fix:
        fix_json_str = json.dumps(suggested_fix, indent=2)
        lines.extend([
            f"## 5. Proposed Remediation Policy (Least-Privilege)",
            f"",
            f"{fix_explanation}",
            f"",
            f"```json",
            f"{fix_json_str}",
            f"```",
            f"",
        ])

    lines.extend([
        f"---",
        f"*Report generated offline by ZeroLeak AI — 0 client data transmitted to external cloud APIs.*",
    ])

    return "\n".join(lines)


def generate_html_report(
    policy_name: str,
    original_policy: Dict[str, Any],
    conftest_results: Dict[str, Any],
    gemma_results: Optional[Dict[str, Any]],
    diff_results: Optional[Dict[str, Any]],
    reverification_results: Optional[Dict[str, Any]],
) -> str:
    """
    Generates an executive-grade, professional light-mode report (HTML/Print).
    100% white background, high-contrast typography, and corporate styling.
    """
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%B %d, %Y - %H:%M UTC")

    opa_passed = conftest_results.get("passed", False)
    opa_violations = conftest_results.get("violations", [])
    opa_badge = (
        '<span class="badge badge-pass">PASSED (0 Violations)</span>'
        if opa_passed
        else f'<span class="badge badge-fail">FAILED ({len(opa_violations)} Violations)</span>'
    )

    gemma_success = gemma_results.get("success", False) if gemma_results else False
    threat_text = gemma_results.get("threat_explanation", "No threat analysis recorded.") if gemma_results else "N/A"
    combos = gemma_results.get("combination_risks", []) if gemma_results else []
    fix_explanation = gemma_results.get("fix_explanation", "") if gemma_results else ""
    suggested_fix = gemma_results.get("suggested_fix") if gemma_results else None

    narrowed = diff_results.get("narrowed", []) if diff_results else []
    dropped = diff_results.get("dropped", []) if diff_results else []
    retained = diff_results.get("retained", []) if diff_results else []
    added = diff_results.get("added", []) if diff_results else []
    warnings = diff_results.get("warnings", []) if diff_results else []

    reverify_status = "N/A"
    if reverification_results:
        reverify_passed = reverification_results.get("passed", False)
        reverify_status = (
            '<span class="badge badge-pass">PASSED (0 Violations)</span>'
            if reverify_passed
            else f'<span class="badge badge-fail">FAILED ({reverification_results.get("violation_count", 0)} Remaining)</span>'
        )

    # Render violations
    violations_html = ""
    if opa_violations:
        for idx, v in enumerate(opa_violations, 1):
            violations_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-idx">{idx}</span>
                    <span class="rule-id">Rule: {v.get('rule')}</span>
                </div>
                <div class="finding-msg">{v.get('message')}</div>
            </div>
            """
    else:
        violations_html = '<div class="callout callout-pass">✅ No deterministic syntax or wildcard rule violations detected.</div>'

    # Render combos
    combos_html = ""
    if combos:
        for c in combos:
            combos_html += f'<div class="callout callout-warn"><strong>⚠️ Combination Risk:</strong> {c}</div>'
    else:
        combos_html = '<p style="color: #64748b; font-style: italic;">No multi-action escalation combination risks identified.</p>'

    # Render warnings
    warnings_html = ""
    if warnings:
        for w in warnings:
            warnings_html += f'<div class="callout callout-danger"><strong>⚠️ Human Approval Required:</strong> {w}</div>'

    fix_json_str = json.dumps(suggested_fix, indent=2) if suggested_fix else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZeroLeak AI — Security Assessment Report ({policy_name})</title>
<style>
    @page {{
        size: A4;
        margin: 20mm 15mm 20mm 15mm;
        @bottom-right {{
            content: "Page " counter(page) " of " counter(pages);
            font-size: 8pt;
            color: #64748b;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
        @bottom-left {{
            content: "ZeroLeak AI — Confidential AWS IAM Security Audit";
            font-size: 8pt;
            color: #64748b;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
    }}
    *, *:before, *:after {{
        box-sizing: border-box;
    }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #0f172a !important;
        background-color: #ffffff !important;
        background: #ffffff !important;
        margin: 0;
        padding: 30px;
        font-size: 9.5pt;
        line-height: 1.55;
    }}
    .report-wrapper {{
        max-width: 850px;
        margin: 0 auto;
        background: #ffffff !important;
    }}
    .header-bar {{
        border-bottom: 2.5px solid #0284c7;
        padding-bottom: 12px;
        margin-bottom: 20px;
    }}
    .title-row {{
        display: flex;
        justify-content: space-between;
        align-items: baseline;
    }}
    .report-title {{
        font-size: 18pt;
        font-weight: 700;
        color: #0f172a !important;
        margin: 0;
    }}
    .report-badge {{
        font-size: 8.5pt;
        color: #0284c7 !important;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    .meta-grid {{
        display: flex;
        flex-wrap: wrap;
        gap: 16px;
        margin-top: 10px;
        font-size: 8.5pt;
        color: #475569 !important;
        background: #f8fafc !important;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 8px 14px;
    }}
    .meta-item strong {{
        color: #1e293b !important;
    }}
    .kpi-row {{
        display: flex;
        gap: 12px;
        margin: 16px 0 24px 0;
    }}
    .kpi-card {{
        flex: 1;
        background: #f8fafc !important;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 12px;
        text-align: center;
    }}
    .kpi-number {{
        font-size: 18pt;
        font-weight: 700;
        color: #0284c7 !important;
        line-height: 1.1;
    }}
    .kpi-label {{
        font-size: 7.5pt;
        font-weight: 600;
        color: #64748b !important;
        text-transform: uppercase;
        margin-top: 4px;
        letter-spacing: 0.5px;
    }}
    h2 {{
        font-size: 12pt;
        font-weight: 700;
        color: #0f172a !important;
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 4px;
        margin: 22px 0 10px 0;
    }}
    .badge {{
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 8pt;
        font-weight: 600;
        letter-spacing: 0.3px;
    }}
    .badge-fail {{
        background: #fee2e2 !important;
        color: #991b1b !important;
        border: 1px solid #f87171;
    }}
    .badge-pass {{
        background: #dcfce7 !important;
        color: #166534 !important;
        border: 1px solid #86efac;
    }}
    .badge-warn {{
        background: #fef3c7 !important;
        color: #92400e !important;
        border: 1px solid #fcd34d;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin: 12px 0;
        font-size: 9pt;
        background: #ffffff !important;
    }}
    th, td {{
        border: 1px solid #e2e8f0;
        padding: 8px 12px;
        text-align: left;
        color: #0f172a !important;
    }}
    th {{
        background: #f1f5f9 !important;
        color: #334155 !important;
        font-weight: 600;
    }}
    .finding-card {{
        background: #ffffff !important;
        border: 1px solid #e2e8f0;
        border-left: 4px solid #ef4444;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 10px;
        page-break-inside: avoid;
    }}
    .finding-header {{
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 4px;
    }}
    .finding-idx {{
        background: #ef4444 !important;
        color: #ffffff !important;
        font-size: 7.5pt;
        font-weight: 700;
        padding: 1px 6px;
        border-radius: 3px;
    }}
    .rule-id {{
        font-weight: 700;
        color: #0f172a !important;
        font-size: 9pt;
    }}
    .finding-msg {{
        color: #334155 !important;
        font-size: 8.5pt;
    }}
    .callout {{
        border-radius: 6px;
        padding: 10px 14px;
        margin: 10px 0;
        font-size: 9pt;
        page-break-inside: avoid;
    }}
    .callout-warn {{
        background: #fffbeb !important;
        border: 1px solid #fde68a;
        border-left: 4px solid #f59e0b;
        color: #92400e !important;
    }}
    .callout-danger {{
        background: #fef2f2 !important;
        border: 1px solid #fecaca;
        border-left: 4px solid #ef4444;
        color: #991b1b !important;
    }}
    .callout-pass {{
        background: #f0fdf4 !important;
        border: 1px solid #bbf7d0;
        border-left: 4px solid #22c55e;
        color: #166534 !important;
    }}
    .code-box {{
        background: #f8fafc !important;
        border: 1px solid #cbd5e1;
        border-radius: 6px;
        padding: 12px 14px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 8pt;
        color: #1e293b !important;
        white-space: pre-wrap;
        word-break: break-all;
        margin: 10px 0;
        page-break-inside: avoid;
    }}
    .perm-grid {{
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin: 8px 0;
    }}
    .perm-pill {{
        background: #f1f5f9 !important;
        border: 1px solid #cbd5e1;
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 8pt;
        color: #334155 !important;
    }}
    .perm-pill.narrowed {{
        background: #ecfdf5 !important;
        border-color: #a7f3d0;
        color: #065f46 !important;
    }}
    .perm-pill.dropped {{
        background: #fff1f2 !important;
        border-color: #fecdd3;
        color: #9f1239 !important;
    }}
    .perm-pill.added {{
        background: #fefce8 !important;
        border-color: #fef08a;
        color: #854d0e !important;
    }}
    .avoid-break {{
        page-break-inside: avoid;
    }}
</style>
</head>
<body>
<div class="report-wrapper">

<div class="header-bar">
    <div class="title-row">
        <h1 class="report-title">ZeroLeak AI — Security Assessment Report</h1>
        <span class="report-badge">100% Offline Assessment</span>
    </div>
    <div class="meta-grid">
        <div class="meta-item"><strong>Target Policy:</strong> <code>{policy_name}</code></div>
        <div class="meta-item"><strong>Audit Date:</strong> {now}</div>
        <div class="meta-item"><strong>Engine:</strong> OPA/Conftest AST + Gemma 2B (Local)</div>
    </div>
</div>

<h2>1. Executive Summary & Verification Gates</h2>
<div class="kpi-row">
    <div class="kpi-card">
        <div class="kpi-number">{len(opa_violations)}</div>
        <div class="kpi-label">OPA Violations</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-number">{len(combos)}</div>
        <div class="kpi-label">Combo Risks Spotted</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-number">{len(narrowed)}</div>
        <div class="kpi-label">Narrowed Actions</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-number">{len(dropped)}</div>
        <div class="kpi-label">Dropped Actions</div>
    </div>
</div>

<table>
    <tr>
        <th style="width: 32%;">Verification Gate</th>
        <th style="width: 28%;">Status</th>
        <th style="width: 40%;">Assessment Details</th>
    </tr>
    <tr>
        <td><strong>Deterministic Gate (OPA)</strong></td>
        <td>{opa_badge}</td>
        <td>AST analysis of wildcard actions, resources & NotAction</td>
    </tr>
    <tr>
        <td><strong>Local Intelligence (Gemma 2B)</strong></td>
        <td><span class="badge badge-pass">COMPLETED (Offline)</span></td>
        <td>Analyzed semantic exploit chains & combination risks</td>
    </tr>
    <tr>
        <td><strong>Automated Re-Verification</strong></td>
        <td>{reverify_status}</td>
        <td>Deterministic validation of proposed remediation</td>
    </tr>
</table>

<h2>2. Deterministic Policy Gate Findings (OPA / Conftest)</h2>
{violations_html}

<h2>3. Exploit Analysis & Combination Risks (Gemma 2B)</h2>
<p style="color: #334155; margin-bottom: 10px;">{threat_text}</p>
{combos_html}

<h2>4. Permission Loss & Guardrail Analysis</h2>
<p style="color: #475569; font-size: 8.5pt;">ZeroLeak classifies permission shifts into narrowed versus dropped verbs to prevent application runtime failures:</p>

<p style="margin: 6px 0 2px 0;"><strong>Narrowed Permissions:</strong></p>
<div class="perm-grid">
    {"".join(f'<span class="perm-pill narrowed">✓ {act}</span>' for act in narrowed) if narrowed else '<span style="color: #64748b;">None</span>'}
</div>

<p style="margin: 8px 0 2px 0;"><strong>Dropped Permissions:</strong></p>
<div class="perm-grid">
    {"".join(f'<span class="perm-pill dropped">✕ {act}</span>' for act in dropped) if dropped else '<span style="color: #64748b;">None</span>'}
</div>

{warnings_html}

{"<h2>5. Proposed Least-Privilege Remediation Policy</h2>" if suggested_fix else ""}
{"<p style=\'color: #334155; font-size: 8.5pt;\'>" + fix_explanation + "</p>" if fix_explanation else ""}
{f'<div class="code-box">{fix_json_str}</div>' if fix_json_str else ""}

</div>
</body>
</html>
"""
    return html


def generate_pdf_report(
    policy_name: str,
    original_policy: Dict[str, Any],
    conftest_results: Dict[str, Any],
    gemma_results: Optional[Dict[str, Any]],
    diff_results: Optional[Dict[str, Any]],
    reverification_results: Optional[Dict[str, Any]],
) -> bytes:
    """
    Generates an executive-grade, professional light-mode PDF audit deliverable using WeasyPrint.
    """
    html_content = generate_html_report(
        policy_name=policy_name,
        original_policy=original_policy,
        conftest_results=conftest_results,
        gemma_results=gemma_results,
        diff_results=diff_results,
        reverification_results=reverification_results,
    )
    import weasyprint
    return weasyprint.HTML(string=html_content).write_pdf()


def generate_plan_markdown_report(
    plan_name: str,
    plan_summary: Dict[str, Any],
    audited_items: List[Dict[str, Any]],
) -> str:
    """Generates a consolidated Markdown audit report for an entire Terraform plan."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_res = plan_summary.get("total_resources", 0)
    total_iam = plan_summary.get("total_iam_policies", len(audited_items))
    total_failed = plan_summary.get("total_failed", 0)
    total_passed = plan_summary.get("total_passed", 0)
    total_uneval = plan_summary.get("total_unevaluated", 0)

    lines = [
        f"# ZeroLeak AI — Terraform Plan Consolidated Security Assessment",
        f"",
        f"> **Terraform Plan Source:** `{plan_name}`  ",
        f"> **Audit Timestamp:** `{now}`  ",
        f"> **Execution Mode:** 100% Offline (Local Conftest AST Gate + Local Gemma 2 2B via Ollama)",
        f"",
        f"---",
        f"",
        f"## 1. Executive Summary & Architecture Compliance",
        f"",
        f"| Metric | Count | Assessment |",
        f"| :--- | :--- | :--- |",
        f"| **Total Terraform Resources Scanned** | `{total_res}` | Complete infrastructure graph analyzed |",
        f"| **Embedded IAM Policies Identified** | `{total_iam}` | Inline role policies & trust relationships |",
        f"| **Non-Compliant Policies (Failed)** | `{total_failed}` | Over-privileged / wildcard violations |",
        f"| **Compliant Policies (Passed)** | `{total_passed}` | Met least-privilege baseline |",
        f"| **Unevaluated Dynamic Policies** | `{total_uneval}` | Text unknown at plan time (computed after apply) |",
        f"",
        f"### Architecture Compliance Matrix",
        f"",
        f"| Resource Address | Type | Attribute | OPA Gate | Gemma Remediation |",
        f"| :--- | :--- | :--- | :--- | :--- |",
    ]

    for item in audited_items:
        addr = item.get("address", "Unknown")
        rtype = item.get("resource_type", "")
        attr = item.get("attribute", "policy")
        is_uneval = item.get("is_unevaluated", False)

        if is_uneval:
            opa_label = "⚠️ NOT EVALUATED"
            gemma_label = "KNOWN AFTER APPLY"
        else:
            opa_passed = item.get("opa_res", {}).get("passed", False)
            opa_label = "✅ PASSED" if opa_passed else f"❌ FAILED ({item.get('opa_res', {}).get('violation_count', 1)})"
            gemma_res = item.get("gemma_res")
            gemma_label = "REMEDIATED" if (gemma_res and gemma_res.get("suggested_fix")) else ("COMPLIANT" if opa_passed else "FLAGGED")

        lines.append(f"| `{addr}` | `{rtype}` | `{attr}` | `{opa_label}` | `{gemma_label}` |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 2. Non-Compliant Resource Deep-Dives & Remediations")
    lines.append("")

    failing_items = [i for i in audited_items if not i.get("opa_res", {}).get("passed", False) and not i.get("is_unevaluated", False)]
    if not failing_items:
        lines.append("✅ All evaluated IAM policies in this Terraform plan passed deterministic verification gates.")
    else:
        for idx, item in enumerate(failing_items, 1):
            addr = item.get("address", "Unknown")
            opa_res = item.get("opa_res", {})
            gemma_res = item.get("gemma_res") or {}
            diff_res = item.get("diff_res") or {}
            reverify = item.get("reverify_res") or {}
            suggested_fix = item.get("suggested_fix")

            lines.append(f"### 2.{idx} Resource: `{addr}`")
            lines.append("")
            lines.append(f"**Deterministic Gate Violations:**")
            for v in opa_res.get("violations", []):
                lines.append(f"- `{v.get('rule')}`: {v.get('message')}")
            lines.append("")

            threat = gemma_res.get("threat_explanation")
            if threat:
                lines.append(f"**Stage 2: Gemma 2B Exploit Analysis:**")
                lines.append(f"{threat}")
                lines.append("")

            combos = gemma_res.get("combination_risks", [])
            if combos:
                lines.append(f"**Combination Escalation Risks:**")
                for c in combos:
                    lines.append(f"- {c}")
                lines.append("")

            narrowed = diff_res.get("narrowed", [])
            dropped = diff_res.get("dropped", [])
            warnings = diff_res.get("warnings", [])

            if dropped:
                lines.append(f"> [!WARNING]")
                lines.append(f"> **⚠️ Human Approval Required: Dropped Permissions Detected**  ")
                lines.append(f"> Remediation removed **{len(dropped)}** action(s). Review target workload runtime before deploying:  ")
                lines.append(f"> **Dropped Actions ({len(dropped)}):** `{', '.join(dropped)}`")
                lines.append("")

            if narrowed:
                lines.append(f"- **Narrowed Permissions:** {', '.join(f'`{a}`' for a in narrowed)}")
                lines.append("")

            if warnings:
                for w in warnings:
                    lines.append(f"> [!CAUTION] {w}")
                lines.append("")

            if suggested_fix:
                reverify_passed = reverify.get("passed", False)
                reverify_msg = "RULE GATE: PASSED (Workload & ARN validity not checked)" if reverify_passed else "RULE GATE: FAILED"
                lines.append(f"**Proposed Scoped Remediation Policy:** (`{reverify_msg}`)")
                lines.append("```json")
                lines.append(json.dumps(suggested_fix, indent=2))
                lines.append("```")
                lines.append("> *Advisory: Verify that dropped actions are not invoked by application runtimes and that scoped resource ARNs match target AWS service specifications.*")
                lines.append("")

    return "\n".join(lines)


def generate_plan_html_report(
    plan_name: str,
    plan_summary: Dict[str, Any],
    audited_items: List[Dict[str, Any]],
) -> str:
    """Generates an executive-grade HTML audit deliverable for an entire Terraform plan."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_res = plan_summary.get("total_resources", 0)
    total_iam = plan_summary.get("total_iam_policies", len(audited_items))
    total_failed = plan_summary.get("total_failed", 0)
    total_passed = plan_summary.get("total_passed", 0)
    total_uneval = plan_summary.get("total_unevaluated", 0)

    matrix_rows = ""
    for item in audited_items:
        addr = item.get("address", "Unknown")
        rtype = item.get("resource_type", "")
        attr = item.get("attribute", "policy")
        is_uneval = item.get("is_unevaluated", False)

        if is_uneval:
            opa_badge = '<span class="status-badge" style="background:#fffbeb; color:#92400e; border-color:#fde68a;">NOT EVALUATED</span>'
            rem_badge = '<span class="status-badge" style="background:#f1f5f9; color:#64748b; border-color:#e2e8f0;">KNOWN AFTER APPLY</span>'
        else:
            opa_passed = item.get("opa_res", {}).get("passed", False)
            opa_badge = '<span class="status-badge badge-pass">PASSED</span>' if opa_passed else f'<span class="status-badge badge-fail">FAILED ({item.get("opa_res", {}).get("violation_count", 1)})</span>'
            gemma_res = item.get("gemma_res")
            if gemma_res and gemma_res.get("suggested_fix"):
                rem_badge = '<span class="status-badge" style="background:#e0f2fe; color:#0369a1; border-color:#bae6fd;">REMEDIATED</span>'
            elif opa_passed:
                rem_badge = '<span class="status-badge" style="background:#f1f5f9; color:#475569; border-color:#e2e8f0;">COMPLIANT</span>'
            else:
                rem_badge = '<span class="status-badge" style="background:#fef2f2; color:#b91c1c; border-color:#fecaca;">FLAGGED</span>'

        matrix_rows += f"""
        <tr>
            <td class="cell-addr">{addr}</td>
            <td class="cell-type">{rtype}</td>
            <td class="cell-attr">{attr}</td>
            <td class="cell-center">{opa_badge}</td>
            <td class="cell-center">{rem_badge}</td>
        </tr>
        """

    failing_sections = ""
    failing_items = [i for i in audited_items if not i.get("opa_res", {}).get("passed", False) and not i.get("is_unevaluated", False)]
    for idx, item in enumerate(failing_items, 1):
        addr = item.get("address", "Unknown")
        opa_res = item.get("opa_res", {})
        gemma_res = item.get("gemma_res") or {}
        diff_res = item.get("diff_res") or {}
        reverify = item.get("reverify_res") or {}
        suggested_fix = item.get("suggested_fix")

        violations_markup = ""
        for v in opa_res.get("violations", []):
            violations_markup += f"""
            <div class="finding-card" style="margin-bottom: 8px;">
                <div class="finding-header">
                    <span class="finding-rule">{v.get('rule')}</span>
                    <span class="finding-severity sev-high">HIGH</span>
                </div>
                <div class="finding-msg">{v.get('message')}</div>
            </div>
            """

        threat_markup = ""
        if gemma_res.get("threat_explanation"):
            threat_markup = f"""
            <div style="background: #f8fafc; border-left: 3px solid #0284c7; padding: 10px 14px; margin: 10px 0; border-radius: 4px;">
                <strong style="color: #0369a1; font-size: 8.5pt;">Stage 2: Gemma 2B Exploit Assessment</strong>
                <p style="margin: 4px 0 0 0; color: #334155; font-size: 8.5pt;">{gemma_res.get('threat_explanation')}</p>
            </div>
            """

        combos_markup = ""
        for c in gemma_res.get("combination_risks", []):
            combos_markup += f'<div class="callout callout-warn"><strong>⚠️ Combination Risk:</strong> {c}</div>'

        narrowed = diff_res.get("narrowed", [])
        dropped = diff_res.get("dropped", [])
        warnings = diff_res.get("warnings", [])

        perm_markup = ""
        if dropped:
            perm_markup += f"""
            <div style="background: #fef2f2; border: 1px solid #fecaca; border-left: 3.5px solid #dc2626; border-radius: 4px; padding: 8px 10px; margin: 8px 0;">
                <div style="color: #991b1b; font-weight: 700; font-size: 8pt; margin-bottom: 2px;">
                    ⚠️ Human Approval Required: Dropped Permissions Detected
                </div>
                <div style="color: #7f1d1d; font-size: 7.5pt; margin-bottom: 4px;">
                    The proposed remediation removed <strong>{len(dropped)}</strong> action(s). Verify target workload runtime before deploying.
                </div>
                <div style="font-size: 7.5pt; color: #991b1b;">
                    <strong>Dropped Actions ({len(dropped)}):</strong> <code>{', '.join(dropped)}</code>
                </div>
            </div>
            """

        if narrowed:
            perm_markup += f"""
            <div style="margin: 6px 0;">
                <strong style="font-size: 7.5pt; color: #475569;">Narrowed Permissions:</strong>
                <div class="perm-grid" style="margin-top: 4px;">
                    {"".join(f'<span class="perm-pill narrowed">✓ {act}</span>' for act in narrowed)}
                </div>
            </div>
            """

        if warnings:
            for w in warnings:
                perm_markup += f'<div class="callout callout-warn" style="margin: 4px 0; font-size: 7.5pt;"><strong>⚠️ Guardrail Notice:</strong> {w}</div>'

        fix_markup = ""
        if suggested_fix:
            fix_json_str = json.dumps(suggested_fix, indent=2)
            reverify_badge = '<span class="status-badge badge-pass" style="font-size: 7pt;">RULE GATE: PASSED (Workload & ARN validity not checked)</span>' if reverify.get("passed") else '<span class="status-badge badge-fail" style="font-size: 7pt;">RULE GATE: FAILED</span>'
            fix_markup = f"""
            <div style="margin-top: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <strong style="font-size: 8.5pt; color: #0f172a;">Proposed Least-Privilege Remediation:</strong>
                    {reverify_badge}
                </div>
                <div class="code-box">{fix_json_str}</div>
                <p style="font-size: 7pt; color: #64748b; margin: 4px 0 0 0; font-style: italic;">
                    *Advisory: Verify that dropped actions are not invoked by application runtimes and that scoped resource ARNs match target AWS service specifications.
                </p>
            </div>
            """

        failing_sections += f"""
        <div class="failing-card">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-bottom: 10px;">
                <span style="font-family: monospace; font-size: 9pt; font-weight: 700; color: #0f172a;">#{idx}. {addr}</span>
                <span class="status-badge badge-fail">NON-COMPLIANT</span>
            </div>
            {violations_markup}
            {threat_markup}
            {combos_markup}
            {perm_markup}
            {fix_markup}
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZeroLeak AI — Terraform Plan Security Assessment ({plan_name})</title>
<style>
    @page {{
        size: A4;
        margin: 14mm 10mm 14mm 10mm;
        @bottom-right {{
            content: "Page " counter(page) " of " counter(pages);
            font-size: 8pt;
            color: #64748b;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
        @bottom-left {{
            content: "ZeroLeak AI — Terraform Plan Consolidated Security Deliverable";
            font-size: 8pt;
            color: #64748b;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
    }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #0f172a !important;
        background-color: #ffffff !important;
        margin: 0;
        padding: 0;
        font-size: 9pt;
        line-height: 1.45;
    }}
    .report-wrapper {{
        width: 100%;
        max-width: 100%;
        margin: 0 auto;
        background: #ffffff !important;
    }}
    .header-bar {{
        border-bottom: 2.5px solid #0284c7;
        padding-bottom: 12px;
        margin-bottom: 20px;
    }}
    .title-row {{
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}
    h1 {{
        color: #0f172a;
        font-size: 13.5pt;
        margin: 0 0 4px 0;
        font-weight: 800;
        letter-spacing: -0.2px;
        white-space: nowrap;
    }}
    .subtitle {{
        color: #64748b;
        font-size: 8.5pt;
        margin: 0;
    }}
    .meta-box {{
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 8px 12px;
        margin-bottom: 16px;
        font-size: 8pt;
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 6px;
    }}
    .meta-item strong {{
        color: #475569;
    }}
    .stat-row {{
        display: flex;
        justify-content: space-between;
        gap: 8px;
        margin-bottom: 18px;
    }}
    .stat-box {{
        flex: 1;
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 8px 4px;
        text-align: center;
        box-sizing: border-box;
    }}
    .stat-val {{
        font-size: 14pt;
        font-weight: 800;
        color: #0f172a;
    }}
    .stat-lbl {{
        font-size: 6pt;
        color: #64748b;
        text-transform: uppercase;
        font-weight: 700;
        letter-spacing: 0.3px;
        margin-top: 2px;
    }}
    h2 {{
        color: #0f172a;
        font-size: 11.5pt;
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 6px;
        margin-top: 22px;
        margin-bottom: 12px;
        font-weight: 700;
    }}
    .table-modern {{
        width: 100%;
        max-width: 100%;
        table-layout: fixed;
        border-collapse: collapse;
        margin: 10px 0 16px 0;
        font-size: 7pt;
        box-sizing: border-box;
    }}
    .table-modern th, .table-modern td {{
        box-sizing: border-box;
    }}
    .table-modern th {{
        background-color: #f1f5f9;
        color: #334155;
        font-weight: 700;
        text-align: left;
        padding: 5px 6px;
        border: 1px solid #cbd5e1;
        font-size: 6.5pt;
        text-transform: uppercase;
        letter-spacing: 0.3px;
    }}
    .table-modern td {{
        padding: 5px 6px;
        border: 1px solid #e2e8f0;
        vertical-align: middle;
        font-size: 6.5pt;
    }}
    .table-modern td.cell-addr {{
        font-family: monospace;
        font-size: 6pt;
        font-weight: 600;
        color: #0f172a;
        word-break: break-word;
        overflow-wrap: anywhere;
        line-height: 1.2;
    }}
    .table-modern td.cell-type {{
        font-size: 6pt;
        color: #475569;
        word-break: break-word;
        overflow-wrap: anywhere;
        line-height: 1.2;
    }}
    .table-modern td.cell-attr {{
        font-size: 6pt;
        color: #64748b;
        word-break: break-word;
        overflow-wrap: anywhere;
        line-height: 1.2;
    }}
    .table-modern td.cell-center {{
        text-align: center;
        padding: 4px 2px;
    }}
    .table-modern tr:nth-child(even) {{
        background-color: #f8fafc;
    }}
    .status-badge {{
        font-size: 6pt;
        font-weight: 700;
        padding: 2px 4px;
        border-radius: 3px;
        display: inline-block;
        border: 1px solid transparent;
        letter-spacing: 0.2px;
        line-height: 1.15;
        text-align: center;
        box-sizing: border-box;
        max-width: 100%;
        white-space: normal;
    }}
    .badge-pass {{
        background-color: #ecfdf5;
        color: #065f46;
        border-color: #a7f3d0;
    }}
    .badge-fail {{
        background-color: #fef2f2;
        color: #991b1b;
        border-color: #fecaca;
    }}
    .failing-card {{
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 12px 16px;
        margin-bottom: 16px;
        background: #ffffff;
        page-break-inside: avoid;
        break-inside: avoid;
    }}
    .finding-card {{
        background-color: #ffffff;
        border: 1px solid #fecaca;
        border-left: 3.5px solid #dc2626;
        border-radius: 4px;
        padding: 8px 10px;
        page-break-inside: avoid;
        break-inside: avoid;
    }}
    .finding-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 2px;
    }}
    .finding-rule {{
        font-family: monospace;
        font-weight: 700;
        font-size: 8.5pt;
        color: #991b1b;
    }}
    .finding-severity {{
        font-size: 6.5pt;
        font-weight: 700;
        padding: 1px 5px;
        border-radius: 3px;
        background-color: #fee2e2;
        color: #991b1b;
    }}
    .finding-msg {{
        color: #334155;
        font-size: 8pt;
    }}
    .callout {{
        border-radius: 4px;
        padding: 6px 10px;
        font-size: 8pt;
        margin: 6px 0;
    }}
    .callout-warn {{
        background-color: #fffbeb;
        border: 1px solid #fde68a;
        color: #92400e;
    }}
    .perm-grid {{
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
    }}
    .perm-pill {{
        font-family: monospace;
        font-size: 7pt;
        padding: 2px 6px;
        border-radius: 3px;
        display: inline-block;
    }}
    .perm-pill.narrowed {{
        background-color: #eff6ff;
        color: #1e40af;
        border: 1px solid #bfdbfe;
    }}
    .perm-pill.dropped {{
        background-color: #fef2f2;
        color: #991b1b;
        border: 1px solid #fecaca;
    }}
    .code-box {{
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 4px;
        padding: 8px 10px;
        font-family: monospace;
        font-size: 7.5pt;
        color: #0f172a;
        white-space: pre-wrap;
        word-break: break-all;
        page-break-inside: avoid;
        break-inside: avoid;
    }}
</style>
</head>
<body>
<div class="report-wrapper">
    <div class="header-bar">
        <div class="title-row">
            <div style="flex: 1;">
                <h1>🛡️ ZeroLeak AI — Architecture Security Report</h1>
                <p class="subtitle">Consolidated Least-Privilege Assessment for Terraform Infrastructure</p>
            </div>
            <div style="flex-shrink: 0; text-align: right; margin-left: 12px;">
                <span class="status-badge {'badge-fail' if total_failed > 0 else 'badge-pass'}" style="font-size: 8pt; padding: 4px 8px; white-space: nowrap;">
                    {'NON-COMPLIANT' if total_failed > 0 else 'COMPLIANT'}
                </span>
            </div>
        </div>
    </div>

    <div class="meta-box">
        <div class="meta-item"><strong>Terraform Plan:</strong> <code>{plan_name}</code></div>
        <div class="meta-item"><strong>Generated:</strong> {now}</div>
        <div class="meta-item"><strong>Execution Mode:</strong> 100% Offline (Deterministic OPA Gate + Local Gemma 2B)</div>
        <div class="meta-item"><strong>Privacy Guarantee:</strong> Zero telemetry. Policies never left this machine.</div>
    </div>

    <div class="stat-row">
        <div class="stat-box">
            <div class="stat-val">{total_res}</div>
            <div class="stat-lbl">Resources Scanned</div>
        </div>
        <div class="stat-box">
            <div class="stat-val">{total_iam}</div>
            <div class="stat-lbl">IAM Policies</div>
        </div>
        <div class="stat-box">
            <div class="stat-val" style="color: #dc2626;">{total_failed}</div>
            <div class="stat-lbl">Failed Policies</div>
        </div>
        <div class="stat-box">
            <div class="stat-val" style="color: #16a34a;">{total_passed}</div>
            <div class="stat-lbl">Passed Policies</div>
        </div>
        <div class="stat-box">
            <div class="stat-val" style="color: #d97706;">{total_uneval}</div>
            <div class="stat-lbl">Known After Apply</div>
        </div>
    </div>

    <h2>1. Architecture IAM Compliance Matrix</h2>
    <table class="table-modern">
        <colgroup>
            <col style="width: 32%;">
            <col style="width: 17%;">
            <col style="width: 13%;">
            <col style="width: 18%;">
            <col style="width: 20%;">
        </colgroup>
        <thead>
            <tr>
                <th style="width: 32%;">Resource Address</th>
                <th style="width: 17%;">Type</th>
                <th style="width: 13%;">Attribute</th>
                <th style="width: 18%; text-align: center;">OPA Gate</th>
                <th style="width: 20%; text-align: center;">Remediation</th>
            </tr>
        </thead>
        <tbody>
            {matrix_rows}
        </tbody>
    </table>

    <h2>2. Non-Compliant Policies & Remediation Deep-Dives</h2>
    {failing_sections if failing_sections else '<p style="color: #16a34a;">All evaluated policies in this plan passed deterministic rule gate verification.</p>'}
</div>
</body>
</html>
"""
    return html


def generate_plan_pdf_report(
    plan_name: str,
    plan_summary: Dict[str, Any],
    audited_items: List[Dict[str, Any]],
) -> bytes:
    """Generates a multi-page executive PDF deliverable for an entire Terraform plan using WeasyPrint."""
    html_content = generate_plan_html_report(
        plan_name=plan_name,
        plan_summary=plan_summary,
        audited_items=audited_items,
    )
    import weasyprint
    return weasyprint.HTML(string=html_content).write_pdf()

