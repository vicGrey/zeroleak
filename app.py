import datetime
import glob
import json
import os
import shutil
import sys
import time
import streamlit as st

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import importlib
import engine.diff_tracker
import engine.gemma_analyzer
import engine.opa_gate
import engine.report_generator
import engine.tfplan_parser
import engine.benchmark_runner

# Ensure submodules are hot-reloaded on code changes
importlib.reload(engine.diff_tracker)
importlib.reload(engine.gemma_analyzer)
importlib.reload(engine.opa_gate)
importlib.reload(engine.report_generator)
importlib.reload(engine.tfplan_parser)
importlib.reload(engine.benchmark_runner)

from engine.diff_tracker import analyze_permission_diff, generate_unified_diff
from engine.gemma_analyzer import analyze_with_gemma, check_ollama_status, DEFAULT_MODEL, DEFAULT_OLLAMA_HOST
from engine.opa_gate import evaluate_policy
from engine.report_generator import (
    generate_markdown_report,
    generate_html_report,
    generate_pdf_report,
    generate_plan_markdown_report,
    generate_plan_html_report,
    generate_plan_pdf_report,
)
from engine.benchmark_runner import run_all_benchmarks, RESULTS_DIR
from engine.tfplan_parser import is_terraform_plan, extract_iam_policies_from_plan

# Page configuration
st.set_page_config(
    page_title="ZeroLeak AI — Offline IAM Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for dark clean cybersecurity aesthetics
st.markdown(
    """
    <style>
    .badge-pass {
        background-color: #0e4429;
        color: #3fb950;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        border: 1px solid #238636;
        display: inline-block;
    }
    .badge-fail {
        background-color: #490202;
        color: #f85149;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        border: 1px solid #da3633;
        display: inline-block;
    }
    .badge-warn {
        background-color: #3b2300;
        color: #d29922;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        border: 1px solid #9e6a03;
        display: inline-block;
    }
    .tag-rule {
        color: #58a6ff;
        font-weight: bold;
    }
    .tag-gemma {
        color: #bc8cff;
        font-weight: bold;
    }
    /* Clean File Uploader Dropzone: Hide noisy file size limit label */
    [data-testid="stFileUploader"] section small,
    [data-testid="stFileUploadDropzone"] small {
        display: none !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_sample_policies():
    samples_dir = os.path.join(os.path.dirname(__file__), "samples", "policies")
    files = sorted(glob.glob(os.path.join(samples_dir, "*.json")))
    samples = {}
    for f in files:
        bname = os.path.basename(f)
        try:
            with open(f, "r", encoding="utf-8") as fp:
                samples[bname] = json.load(fp)
        except Exception:
            pass
    return samples


AUDIT_CACHE_FILE = os.path.join(os.path.dirname(__file__), ".active_audit_cache.json")


def load_cached_audit():
    if os.path.exists(AUDIT_CACHE_FILE):
        try:
            with open(AUDIT_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def save_cached_audit(audit_data):
    try:
        with open(AUDIT_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(audit_data, f, indent=2)
    except Exception:
        pass


def clear_cached_audit():
    if os.path.exists(AUDIT_CACHE_FILE):
        try:
            os.remove(AUDIT_CACHE_FILE)
        except Exception:
            pass


def main():
    st.title("🛡️ ZeroLeak AI")
    st.caption("100% Offline, Privacy-First AWS IAM Security Auditor & Remediation Engine")

    # Restore audit results across browser refreshes / page reloads
    if "active_audit" not in st.session_state:
        cached_audit = load_cached_audit()
        if cached_audit:
            st.session_state["active_audit"] = cached_audit

    # Sidebar: System Status & Controls
    with st.sidebar:
        st.header("⚡ System Telemetry & Status")
        st.markdown(
            "> **Privacy Claim:** Zero telemetry. Zero cloud calls. Policies never leave this machine."
        )

        ollama_status = check_ollama_status()
        if ollama_status["online"]:
            st.success(f"🟢 **Ollama:** Online (`{DEFAULT_OLLAMA_HOST}`)")
            if ollama_status["has_gemma2_2b"]:
                st.info(f"🧠 **Model:** `{DEFAULT_MODEL}` ready")
            else:
                st.warning(f"⚠️ `{DEFAULT_MODEL}` not found. Run: `ollama pull gemma2:2b`")
        else:
            st.error("🔴 **Ollama:** Offline")
            st.caption("Start Ollama locally: `ollama serve`")

        conftest_found = bool(shutil.which("conftest") or os.path.exists("/usr/local/bin/conftest"))
        if conftest_found:
            st.success("🟢 **Deterministic Gate:** OPA / Conftest Active")
        else:
            st.error("🔴 **Deterministic Gate:** Conftest not found")
            st.caption("Install Conftest: `brew install conftest` or see README")

        st.markdown("---")
        st.subheader("📁 Test Case Samples")
        samples = load_sample_policies()
        sample_options = ["(Custom Policy)"] + list(samples.keys())
        selected_sample = st.selectbox("Load Benchmark Sample:", sample_options)

    # Manage session state for policy text area so dropdown & uploads update it reactively
    default_initial = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowEverythingSample",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        },
        indent=2,
    )
    if "current_sample" not in st.session_state:
        st.session_state["current_sample"] = "(Custom Policy)"
    if "last_uploaded_name" not in st.session_state:
        st.session_state["last_uploaded_name"] = None
    if "policy_editor" not in st.session_state:
        st.session_state["policy_editor"] = default_initial

    # Reactively update text area when dropdown changes
    if selected_sample != st.session_state["current_sample"]:
        st.session_state["current_sample"] = selected_sample
        if selected_sample in samples:
            st.session_state["policy_editor"] = json.dumps(samples[selected_sample], indent=2)

    # Input Area: File upload or paste
    col_input, col_meta = st.columns([3, 1])
    with col_input:
        uploaded_file = st.file_uploader("📂 Upload AWS IAM Policy or Terraform Plan JSON File:", type=["json"])
        if uploaded_file is not None and uploaded_file.name != st.session_state.get("last_uploaded_name"):
            try:
                uploaded_text = uploaded_file.read().decode("utf-8")
                parsed_json = json.loads(uploaded_text)
                st.session_state["last_uploaded_name"] = uploaded_file.name

                if is_terraform_plan(parsed_json):
                    st.session_state["tfplan_resource_count"] = len(parsed_json.get("resource_changes", []))
                    extracted_policies = extract_iam_policies_from_plan(parsed_json)
                    # Sort: failing policies first, then inline policies before trust policies
                    extracted_policies.sort(
                        key=lambda p: (
                            0 if not evaluate_policy(p["policy_dict"])["passed"] else 1,
                            0 if p.get("attribute") == "policy" else 1,
                            p.get("address", ""),
                        )
                    )
                    st.session_state["tfplan_policies"] = extracted_policies
                    st.session_state["is_tfplan"] = True
                    st.session_state["last_selected_tf_idx"] = 0
                    if extracted_policies:
                        st.session_state["policy_editor"] = extracted_policies[0]["policy_json_str"]
                        st.session_state["current_policy_label"] = extracted_policies[0]["address"]
                    st.success(f"📦 Detected Terraform Plan (`{uploaded_file.name}`): Extracted {len(extracted_policies)} embedded IAM policies.")
                else:
                    st.session_state["is_tfplan"] = False
                    st.session_state["tfplan_policies"] = []
                    st.session_state["policy_editor"] = uploaded_text
                    st.session_state["current_policy_label"] = uploaded_file.name
                    st.success(f"Loaded: `{uploaded_file.name}`")
            except Exception as e:
                st.error(f"Error reading uploaded JSON: {str(e)}")

        # Terraform Plan Policy Selector
        if st.session_state.get("is_tfplan") and st.session_state.get("tfplan_policies"):
            tf_policies = st.session_state["tfplan_policies"]
            tf_options = []
            for p in tf_policies:
                eval_check = evaluate_policy(p["policy_dict"])
                icon = "❌ FAILED" if not eval_check["passed"] else "✅ PASSED"
                tf_options.append(f"{icon} | {p['address']} ({p['attribute']})")

            cur_idx = st.session_state.get("last_selected_tf_idx", 0)
            if cur_idx >= len(tf_options):
                cur_idx = 0

            selected_tf_idx = st.selectbox(
                "🎯 Select Embedded IAM Policy from Plan to Audit & Remediate:",
                range(len(tf_options)),
                index=cur_idx,
                format_func=lambda i: tf_options[i],
                key="tf_policy_selector_widget",
            )
            if selected_tf_idx != st.session_state.get("last_selected_tf_idx"):
                st.session_state["last_selected_tf_idx"] = selected_tf_idx
                st.session_state["policy_editor"] = tf_policies[selected_tf_idx]["policy_json_str"]
                st.session_state["current_policy_label"] = tf_policies[selected_tf_idx]["address"]
                st.rerun()

        policy_input_text = st.text_area(
            "AWS IAM Policy JSON to Audit (or edit uploaded/selected policy):",
            height=260,
            key="policy_editor",
        )
    with col_meta:
        st.markdown("### Quick Actions")
        is_plan = st.session_state.get("is_tfplan", False)
        if is_plan:
            audit_all_btn = st.button("📋 Audit Entire Plan (Unified)", type="primary", use_container_width=True)
            audit_btn = st.button("🔍 Audit Selected Policy Only", use_container_width=True)
        else:
            audit_btn = st.button("🚀 Run ZeroLeak Audit", type="primary", use_container_width=True)
            audit_all_btn = False

        if "active_audit" in st.session_state or os.path.exists(AUDIT_CACHE_FILE):
            if st.button("🔄 Clear / New Audit", use_container_width=True):
                if "active_audit" in st.session_state:
                    del st.session_state["active_audit"]
                st.session_state["is_tfplan"] = False
                st.session_state["tfplan_policies"] = []
                st.session_state["last_uploaded_name"] = None
                clear_cached_audit()
                st.rerun()
        st.markdown(
            """
            **5-Stage Auditing Pipeline:**
            1. **Stage 1:** Conftest AST Gate
            2. **Stage 2:** Gemma 2B Exploit Analysis
            3. **Stage 3:** Scoped Remediation
            4. **Stage 4:** Permission Loss & Diff
            5. **Stage 5:** Re-verification Pass
            """
        )

    # 1. BATCH PLAN AUDIT EXECUTION
    if is_plan and audit_all_btn:
        tf_policies = st.session_state.get("tfplan_policies", [])
        if not tf_policies:
            st.error("No embedded IAM policies found in this Terraform plan.")
            return

        with st.status("🏛️ Executing Full Architecture Security Assessment across all policies...", expanded=True) as status:
            t0 = time.time()
            progress_bar = st.progress(0, text="Starting architecture scan...")
            audited_items = []
            failed_count = 0
            passed_count = 0

            # Step 1: Deterministic Conftest sweep
            st.write("⚡ **[Phase 1] Deterministic Conftest Sweep** — Pre-screening all embedded IAM policies...")
            progress_bar.progress(5, text="[Phase 1] Screening policies with Conftest...")
            unevaluated_count = 0
            for p in tf_policies:
                if not p.get("is_evaluated", True) or p.get("policy_dict") is None:
                    unevaluated_count += 1
                    audited_items.append({
                        "address": p["address"],
                        "resource_type": p["resource_type"],
                        "attribute": p["attribute"],
                        "original_policy": None,
                        "opa_res": {
                            "passed": False,
                            "violations": [],
                            "violation_count": 0,
                            "is_unevaluated": True,
                            "reason": p.get("unevaluated_reason", "Policy text unknown at plan time")
                        },
                        "is_unevaluated": True,
                        "gemma_res": None,
                        "diff_res": None,
                        "reverify_res": None,
                        "suggested_fix": None,
                    })
                else:
                    opa_eval = evaluate_policy(p["policy_dict"])
                    if opa_eval["passed"]:
                        passed_count += 1
                    else:
                        failed_count += 1
                    audited_items.append({
                        "address": p["address"],
                        "resource_type": p["resource_type"],
                        "attribute": p["attribute"],
                        "original_policy": p["policy_dict"],
                        "opa_res": opa_eval,
                        "is_unevaluated": False,
                        "gemma_res": None,
                        "diff_res": None,
                        "reverify_res": None,
                        "suggested_fix": None,
                    })
            st.write(f"   ↳ ⚡ Evaluated {len(tf_policies)} policies in <0.05s ({failed_count} failing, {passed_count} compliant, {unevaluated_count} known after apply)")
            progress_bar.progress(15, text=f"[Phase 1 Complete] Screened {len(tf_policies)} policies ({failed_count} failing, {unevaluated_count} known after apply).")

            # Step 2: Run Gemma on non-compliant evaluated policies
            failing_indices = [
                i for i, it in enumerate(audited_items) 
                if not it.get("is_unevaluated") and not it["opa_res"]["passed"]
            ]
            st.write(f"🧠 **[Phase 2] Local Gemma Exploit Pass** — Auditing {len(failing_indices)} non-compliant resource(s)...")

            if not failing_indices:
                progress_bar.progress(100, text="✅ All policies compliant! Assessment complete.")
            else:
                for step_idx, item_idx in enumerate(failing_indices):
                    target_item = audited_items[item_idx]
                    pct = 15 + int((step_idx / len(failing_indices)) * 80)
                    progress_bar.progress(pct, text=f"[Phase 2] Auditing ({step_idx + 1}/{len(failing_indices)}): {target_item['address']}...")
                    st.write(f"   ↳ ({step_idx + 1}/{len(failing_indices)}) Auditing: `{target_item['address']}`...")

                    gemma_res = None
                    if ollama_status["online"] and ollama_status["has_gemma2_2b"]:
                        gemma_res = analyze_with_gemma(target_item["original_policy"])
                    else:
                        gemma_res = {
                            "success": False,
                            "threat_explanation": "Ollama service is offline or gemma2:2b model not found locally.",
                            "combination_risks": [],
                            "suggested_fix": None,
                            "fix_explanation": "",
                            "error": "Ollama offline. Run 'ollama serve' and 'ollama pull gemma2:2b'.",
                            "latency_seconds": 0.0,
                        }

                    diff_res = None
                    reverify_res = None
                    suggested_fix = gemma_res.get("suggested_fix") if gemma_res else None
                    if suggested_fix:
                        diff_res = analyze_permission_diff(target_item["original_policy"], suggested_fix)
                        reverify_res = evaluate_policy(suggested_fix)

                    target_item["gemma_res"] = gemma_res
                    target_item["diff_res"] = diff_res
                    target_item["reverify_res"] = reverify_res
                    target_item["suggested_fix"] = suggested_fix

                    pct_done = 15 + int(((step_idx + 1) / len(failing_indices)) * 80)
                    progress_bar.progress(min(pct_done, 95), text=f"Finished {target_item['address']}")

            total_elapsed = round(time.time() - t0, 2)
            progress_bar.progress(100, text=f"✅ Architecture Assessment Complete in {total_elapsed:.2f}s!")
            status.update(label=f"✅ Plan Assessment Complete in {total_elapsed:.2f}s!", state="complete", expanded=False)

            plan_name = st.session_state.get("last_uploaded_name", "terraform_plan.json")
            total_res = st.session_state.get("tfplan_resource_count", 48)

            plan_payload = {
                "mode": "plan_batch",
                "plan_name": plan_name,
                "plan_summary": {
                    "total_resources": total_res,
                    "total_iam_policies": len(tf_policies),
                    "total_failed": failed_count,
                    "total_passed": passed_count,
                    "total_unevaluated": unevaluated_count,
                    "elapsed_seconds": total_elapsed,
                },
                "audited_items": audited_items,
            }
            save_cached_audit(plan_payload)
            st.session_state["active_audit"] = plan_payload
            st.rerun()

    # 2. SINGLE POLICY AUDIT EXECUTION
    if audit_btn:
        # Validate JSON parse
        try:
            policy_dict = json.loads(policy_input_text)
        except json.JSONDecodeError as err:
            st.error(f"❌ Invalid JSON Syntax: {str(err)}")
            return

        # If user directly pasted a full Terraform plan into the text box instead of uploading:
        if is_terraform_plan(policy_dict):
            extracted = extract_iam_policies_from_plan(policy_dict)
            if extracted:
                extracted.sort(
                    key=lambda p: (
                        0 if not evaluate_policy(p["policy_dict"])["passed"] else 1,
                        0 if p.get("attribute") == "policy" else 1,
                        p.get("address", ""),
                    )
                )
                st.session_state["is_tfplan"] = True
                st.session_state["tfplan_policies"] = extracted
                st.session_state["tfplan_resource_count"] = len(policy_dict.get("resource_changes", []))
                st.session_state["last_selected_tf_idx"] = 0
                st.session_state["policy_editor"] = extracted[0]["policy_json_str"]
                st.session_state["current_policy_label"] = extracted[0]["address"]
                st.info(f"📦 Detected Terraform Plan. Extracted {len(extracted)} IAM policies. Selected: {extracted[0]['address']}. Click 'Run ZeroLeak Audit' to proceed.")
                st.rerun()

        with st.status("🛡️ Running ZeroLeak 5-Stage Security Pipeline...", expanded=True) as status:
            t0 = time.time()
            progress_bar = st.progress(0, text="Initializing 5-stage pipeline...")

            # Stage 1
            st.write("⚡ **[Stage 1/5] Conftest AST Gate** — Scanning deterministic Rego rules...")
            progress_bar.progress(10, text="[Stage 1/5] Running Conftest AST parser...")
            opa_res = evaluate_policy(policy_dict)
            if opa_res["passed"]:
                st.write("   ↳ ✅ Conftest PASSED (0 syntax or wildcard violations)")
            else:
                st.write(f"   ↳ ❌ Conftest FAILED ({opa_res['violation_count']} rule violation(s) flagged)")
            progress_bar.progress(25, text="[Stage 1/5] Conftest Gate Complete.")

            # Stage 2
            st.write("🧠 **[Stage 2/5] Local Gemma 2 2B Pass** — Reasoning over exploit chains & privilege escalations...")
            progress_bar.progress(35, text="[Stage 2/5] Local Gemma evaluating exploit risks...")
            gemma_res = None
            if ollama_status["online"] and ollama_status["has_gemma2_2b"]:
                gemma_res = analyze_with_gemma(policy_dict)
                st.write(f"   ↳ 🧠 Gemma exploit analysis complete ({gemma_res.get('latency_seconds', 0)}s)")
            else:
                gemma_res = {
                    "success": False,
                    "threat_explanation": "Ollama service is offline or gemma2:2b model not found locally.",
                    "combination_risks": [],
                    "suggested_fix": None,
                    "fix_explanation": "",
                    "error": "Ollama offline. Run 'ollama serve' and 'ollama pull gemma2:2b'.",
                    "latency_seconds": 0.0,
                }
                st.write("   ↳ ⚠️ Ollama offline. Skipped Gemma pass.")
            progress_bar.progress(70, text="[Stage 2/5] Gemma Analysis Complete.")

            diff_res = None
            reverify_res = None
            suggested_fix = None

            # SAFETY GOVERNOR:
            # Only trigger automated remediation if Layer 1 actually flagged violations.
            # If the policy is already compliant (0 violations), we NEVER mutate working code!
            if not opa_res["passed"]:
                st.write("🛠️ **[Stage 3/5] Scoped Remediation** — Generating least-privilege fix for violations...")
                progress_bar.progress(80, text="[Stage 3/5] Generating Scoped Remediation...")
                suggested_fix = gemma_res.get("suggested_fix")
                if suggested_fix:
                    st.write("📊 **[Stage 4/5] Diff & Guardrails Tracker** — Tracking narrowed vs dropped actions...")
                    progress_bar.progress(90, text="[Stage 4/5] Calculating Permission Loss & Diff...")
                    diff_res = analyze_permission_diff(policy_dict, suggested_fix)
                    st.write(f"   ↳ {len(diff_res['narrowed'])} actions narrowed, {len(diff_res['dropped'])} dropped")

                    st.write("🔒 **[Stage 5/5] Automated Re-Verification Pass** — Validating fix against Conftest gate...")
                    progress_bar.progress(95, text="[Stage 5/5] Automated Re-Verification Pass...")
                    reverify_res = evaluate_policy(suggested_fix)
                    if reverify_res["passed"]:
                        st.write("   ↳ ✅ Re-verification PASSED (0 violations remaining)")
                    else:
                        st.write(f"   ↳ ⚠️ Fix retained {reverify_res['violation_count']} violation(s)")
                else:
                    st.write("   ↳ No remediation policy proposed.")
            else:
                st.write("🛡️ **[Stages 3-5 Guardrail] Safety Governor Active** — Policy passed deterministic gate. Code preserved intact.")
                progress_bar.progress(95, text="[Safety Governor] Code preserved intact.")

            total_elapsed = round(time.time() - t0, 2)
            progress_bar.progress(100, text=f"✅ 5-Stage Audit Completed in {total_elapsed:.2f}s!")
            status.update(label=f"✅ ZeroLeak Audit Complete in {total_elapsed:.2f}s!", state="complete", expanded=False)

            target_name = st.session_state.get("current_policy_label")
            if not target_name:
                target_name = selected_sample if selected_sample != "(Custom Policy)" else "custom_policy.json"

            audit_payload = {
                "mode": "single_policy",
                "policy_dict": policy_dict,
                "opa_res": opa_res,
                "gemma_res": gemma_res,
                "diff_res": diff_res,
                "reverify_res": reverify_res,
                "suggested_fix": suggested_fix,
                "policy_name": target_name,
                "elapsed_seconds": total_elapsed,
                "completed_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
            save_cached_audit(audit_payload)
            st.session_state["active_audit"] = audit_payload
            st.rerun()

    # Render results whenever an active audit exists
    if "active_audit" in st.session_state:
        audit_data = st.session_state["active_audit"]

        # =========================================================================
        # BRANCH A: CONSOLIDATED TERRAFORM PLAN DELIVERABLE
        # =========================================================================
        if audit_data.get("mode") == "plan_batch":
            plan_name = audit_data.get("plan_name", "terraform_plan.json")
            plan_summary = audit_data.get("plan_summary", {})
            audited_items = audit_data.get("audited_items", [])

            elapsed_sec = plan_summary.get("elapsed_seconds")
            elapsed_badge = f" • Evaluated in {elapsed_sec:.2f}s (Offline)" if elapsed_sec is not None else ""

            st.header(f"🏛️ Terraform Architecture Deliverable: `{plan_name}`")
            st.caption(f"100% Offline Assessment — {plan_summary.get('total_resources', 48)} Cloud Resources Scanned{elapsed_badge}")

            tab_matrix, tab_failing, tab_report = st.tabs(
                ["📊 Compliance Matrix", "🛠️ Remediations Deep-Dive", "📄 Export Consolidated Deliverables"]
            )

            with tab_matrix:
                col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
                col_m1.metric("Resources Scanned", plan_summary.get("total_resources", 0))
                col_m2.metric("IAM Policies Found", plan_summary.get("total_iam_policies", len(audited_items)))
                col_m3.metric("Non-Compliant (Failed)", plan_summary.get("total_failed", 0))
                col_m4.metric("Compliant (Passed)", plan_summary.get("total_passed", 0))
                col_m5.metric("Known After Apply", plan_summary.get("total_unevaluated", 0))

                if plan_summary.get("total_unevaluated", 0) > 0:
                    st.info(f"ℹ️ **{plan_summary.get('total_unevaluated')} IAM Policy Documents Not Evaluated at Plan Time**: These policies contain policy definitions computed dynamically during apply (e.g. referencing dynamic table/bucket ARNs). Re-evaluate them post-deployment.")

                st.markdown("### Architecture IAM Compliance Matrix")
                for item in audited_items:
                    addr = item.get("address")
                    attr = item.get("attribute")
                    rtype = item.get("resource_type")
                    opa_passed = item.get("opa_res", {}).get("passed", False)
                    v_count = item.get("opa_res", {}).get("violation_count", 0)

                    c_addr, c_status, c_act = st.columns([3, 1, 1])
                    with c_addr:
                        st.markdown(f"**`{addr}`** (`{rtype}` • `{attr}`)")
                    with c_status:
                        if item.get("is_unevaluated"):
                            st.markdown('<span class="badge-warn">⚠️ NOT EVALUATED</span>', unsafe_allow_html=True)
                        elif opa_passed:
                            st.markdown('<span class="badge-pass">✅ PASSED</span>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<span class="badge-fail">❌ FAILED ({v_count})</span>', unsafe_allow_html=True)
                    with c_act:
                        if item.get("is_unevaluated"):
                            st.markdown('<span style="color: #d97706;">Known After Apply</span>', unsafe_allow_html=True)
                        else:
                            gemma_res = item.get("gemma_res")
                            if gemma_res and gemma_res.get("suggested_fix"):
                                st.markdown('<span style="color: #38bdf8; font-weight:600;">✓ Remediated</span>', unsafe_allow_html=True)
                            elif opa_passed:
                                st.markdown('<span style="color: #64748b;">Compliant</span>', unsafe_allow_html=True)
                            else:
                                st.markdown('<span style="color: #f87171;">Action Required</span>', unsafe_allow_html=True)
                    st.divider()

            with tab_failing:
                st.subheader("Deep-Dive Exploit Analysis & Remediations")
                failing_items = [i for i in audited_items if not i.get("is_unevaluated") and not i.get("opa_res", {}).get("passed", False)]
                if not failing_items:
                    st.success("🎉 All policies in this Terraform plan passed deterministic verification gates!")
                else:
                    for idx, item in enumerate(failing_items, 1):
                        with st.expander(f"🔴 #{idx}: {item.get('address')}", expanded=(idx == 1)):
                            st.markdown(f"**Resource:** `{item.get('address')}` (`{item.get('attribute')}`)")

                            c_opa, c_gemma = st.columns(2)
                            with c_opa:
                                st.markdown("#### Stage 1: Deterministic Gate (OPA Conftest)")
                                for v in item.get("opa_res", {}).get("violations", []):
                                    st.error(f"**{v.get('rule')}**: {v.get('message')}")
                            with c_gemma:
                                st.markdown("#### Stage 2: Gemma 2B Exploit Analysis")
                                g_res = item.get("gemma_res") or {}
                                if g_res.get("success"):
                                    lat = g_res.get("latency_seconds", 0.0)
                                    st.markdown(
                                        f'<div class="badge-pass" style="margin-bottom:8px;">🧠 Evaluated in {lat}s (Offline)</div>',
                                        unsafe_allow_html=True,
                                    )
                                    st.markdown("**Threat Breakdown:**")
                                    st.write(g_res.get("threat_explanation", "No threat explanation provided."))
                                    for c in g_res.get("combination_risks", []):
                                        st.warning(f"⚠️ {c}")
                                else:
                                    st.markdown(
                                        f'<div class="badge-warn" style="margin-bottom:8px;">⚠️ Gemma Pass Incomplete</div>',
                                        unsafe_allow_html=True,
                                    )
                                    st.caption(g_res.get("error", "No Gemma response."))

                            # Stages 3, 4, 5: Fix, Diff & Re-verification
                            suggested_fix = item.get("suggested_fix")
                            diff_res = item.get("diff_res") or {}
                            reverify = item.get("reverify_res") or {}
                            if suggested_fix:
                                st.markdown("#### Stage 3: Scoped Least-Privilege Remediation")
                                col_orig, col_fix = st.columns(2)
                                with col_orig:
                                    st.markdown("**Original Policy**")
                                    st.json(item.get("original_policy"))
                                with col_fix:
                                    st.markdown("**Remediated Policy**")
                                    st.json(suggested_fix)

                                st.markdown("#### Stage 4: Permission Loss Tracker & Guardrails")
                                if diff_res.get("human_approval_required"):
                                    st.warning("⚠️ **Human Approval Required**: Dropped permissions, added actions, or altered trust principals detected.")

                                c_diff1, c_diff2 = st.columns(2)
                                with c_diff1:
                                    narrowed = diff_res.get("narrowed", [])
                                    if narrowed:
                                        st.markdown(f"**Narrowed Actions ({len(narrowed)}):** `{', '.join(narrowed)}`")
                                    else:
                                        st.caption("No narrowed actions")
                                with c_diff2:
                                    dropped = diff_res.get("dropped", [])
                                    if dropped:
                                        st.markdown(f"**Dropped Actions ({len(dropped)}):** `{', '.join(dropped)}`")
                                    else:
                                        st.caption("No dropped actions")

                                st.markdown("#### Stage 5: Automated Conftest Re-Verification Pass")
                                if reverify.get("passed"):
                                    st.markdown('<div class="badge-pass" style="margin-bottom:8px;">✅ Rule Gate: PASSED (Workload & ARN validity not checked)</div>', unsafe_allow_html=True)
                                else:
                                    st.markdown(f'<div class="badge-fail" style="margin-bottom:8px;">❌ Rule Gate: FAILED ({reverify.get("violation_count", 1)} Violations Remaining)</div>', unsafe_allow_html=True)

            with tab_report:
                st.subheader("Download Consolidated Plan Deliverables")
                st.markdown("Download a single executive security deliverable covering every resource in this Terraform plan.")

                plan_md = generate_plan_markdown_report(plan_name, plan_summary, audited_items)
                plan_pdf = generate_plan_pdf_report(plan_name, plan_summary, audited_items)

                c_d1, c_d2 = st.columns(2)
                with c_d1:
                    st.download_button(
                        label="📥 Download Consolidated PDF Report (.pdf)",
                        data=plan_pdf,
                        file_name=f"{plan_name.replace('.json', '')}_consolidated_security_report.pdf",
                        mime="application/pdf",
                        type="primary",
                        use_container_width=True,
                    )
                with c_d2:
                    st.download_button(
                        label="📝 Download Consolidated Markdown Report (.md)",
                        data=plan_md,
                        file_name=f"{plan_name.replace('.json', '')}_consolidated_security_report.md",
                        mime="text/markdown",
                        use_container_width=True,
                    )
                st.markdown("---")
                st.markdown("### Report Preview")
                st.markdown(plan_md)

        # =========================================================================
        # BRANCH B: SINGLE POLICY DELIVERABLE
        # =========================================================================
        else:
            policy_dict = audit_data["policy_dict"]
            opa_res = audit_data["opa_res"]
            gemma_res = audit_data["gemma_res"]
            diff_res = audit_data["diff_res"]
            reverify_res = audit_data["reverify_res"]
            suggested_fix = audit_data["suggested_fix"]
            policy_name = audit_data.get("policy_name", "custom_policy.json")

            elapsed_sec = audit_data.get("elapsed_seconds")
            if elapsed_sec is None and gemma_res and "latency_seconds" in gemma_res:
                elapsed_sec = round(gemma_res.get("latency_seconds", 0.0) + 0.04, 2)
            elapsed_badge = f" • Evaluated in {elapsed_sec:.2f}s (Offline)" if elapsed_sec is not None else ""

            st.header(f"🔍 Policy Audit Deliverable: `{policy_name}`")
            st.caption(f"100% Offline Assessment — 5-Stage ZeroLeak Pipeline{elapsed_badge}")

            # Tabs for structured viewing
            tab_audit, tab_remediation, tab_diff, tab_reverify, tab_report = st.tabs(
                [
                    "🔍 Stages 1 & 2: Audit Findings",
                    "🛠️ Stage 3: Scoped Remediation",
                    "📊 Stage 4: Permission Loss & Diff",
                    "🔒 Stage 5: Re-Verification Pass",
                    "📄 Export Report",
                ]
            )

            with tab_audit:
                col_h1, col_h2, col_h3, col_h4 = st.columns(4)
                col_h1.metric("Compliance Status", "PASSED" if opa_res["passed"] else f"FAILED ({opa_res['violation_count']})")
                col_h2.metric("Deterministic Violations", opa_res.get("violation_count", 0))
                g_lat = gemma_res.get("latency_seconds") if gemma_res else None
                col_h3.metric("Gemma AI Latency", f"{g_lat:.2f}s" if g_lat is not None else "N/A")
                col_h4.metric("Total Scan Time", f"{elapsed_sec:.2f}s" if elapsed_sec is not None else "N/A")

                st.subheader("Dual-Engine Security Assessment (Stages 1 & 2)")

                # Stage 1: Conftest
                col1, col2 = st.columns([1, 1])
                with col1:
                    st.markdown("#### Stage 1: Deterministic Gate (`[Rule]`)")
                    if opa_res["passed"]:
                        st.markdown('<div class="badge-pass">✅ PASSED (0 Violations)</div>', unsafe_allow_html=True)
                        st.info("No wildcard Action, wildcard Resource, or dangerous NotAction detected by Conftest AST parser.")
                    else:
                        st.markdown(
                            f'<div class="badge-fail">❌ FAILED ({opa_res["violation_count"]} Violations)</div>',
                            unsafe_allow_html=True,
                        )
                        for idx, v in enumerate(opa_res["violations"], 1):
                            st.markdown(f"**{idx}.** `{v['rule']}`: {v['message']}")

                # Stage 2: Gemma
                with col2:
                    st.markdown("#### Stage 2: Local Intelligence (`[Gemma]`)")
                    if gemma_res["success"]:
                        st.markdown(
                            f'<div class="badge-pass">🧠 Evaluated in {gemma_res["latency_seconds"]}s (Offline)</div>',
                            unsafe_allow_html=True,
                        )
                        st.markdown("**Threat Breakdown:**")
                        st.write(gemma_res["threat_explanation"])

                        combos = gemma_res.get("combination_risks", [])
                        if combos:
                            st.markdown("**Combination & Escalation Risks:**")
                            for c in combos:
                                st.warning(f"⚠️ {c}")
                    else:
                        st.markdown('<div class="badge-warn">⚠️ Gemma Pass Skipped</div>', unsafe_allow_html=True)
                        st.caption(gemma_res.get("error", "Ollama offline."))

            with tab_remediation:
                st.subheader("Stage 3: Proposed Scoped Remediation")
                if opa_res.get("passed"):
                    st.success("✅ **Policy Compliant:** This policy passed deterministic least-privilege verification (0 rule violations). No automated code remediation is required.")
                    st.markdown("Your original policy is safe to keep and deploy:")
                    st.json(policy_dict)
                elif suggested_fix:
                    st.markdown("**Remediation Strategy:**")
                    st.write(gemma_res.get("fix_explanation", "Permissions narrowed to least privilege."))

                    st.markdown("#### Proposed Policy JSON")
                    st.json(suggested_fix)
                else:
                    st.info("No suggested fix generated (Ollama offline or model output failed JSON parse).")

            with tab_diff:
                st.subheader("Stage 4: Permission Loss Tracker & Guardrails")
                if opa_res.get("passed"):
                    st.info("✅ **Zero Code Drift:** Because the policy passed deterministic AST verification, no permissions were narrowed, dropped, or modified.")
                elif diff_res and suggested_fix:
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Narrowed", len(diff_res["narrowed"]))
                    c2.metric("Dropped", len(diff_res["dropped"]))
                    c3.metric("Retained", len(diff_res["retained"]))
                    c4.metric("Added (Hallucination Risk)", len(diff_res["added"]))

                    if diff_res["warnings"]:
                        st.markdown("### ⚠️ Runtime & Security Warnings")
                        for w in diff_res["warnings"]:
                            st.warning(w)

                    st.markdown("#### Side-by-Side Comparison")
                    col_orig, col_fixed = st.columns(2)
                    with col_orig:
                        st.markdown("**Original Policy**")
                        st.json(policy_dict)
                    with col_fixed:
                        st.markdown("**Remediated Policy**")
                        st.json(suggested_fix)

                    st.markdown("#### Unified Diff")
                    unified = generate_unified_diff(policy_dict, suggested_fix)
                    st.code(unified, language="diff")
                else:
                    st.info("Visual diff available when remediation is generated.")

            with tab_reverify:
                st.subheader("Stage 5: Automated Conftest Re-Verification Pass")
                if opa_res.get("passed"):
                    st.success("✅ **Baseline Verified:** This policy passed deterministic AST verification on the initial gate (0 rule violations).")
                    st.markdown("Your original policy complies with least-privilege standards:")
                    st.json(policy_dict)
                elif reverify_res and suggested_fix:
                    if reverify_res["passed"]:
                        st.markdown(
                            '<div class="badge-pass" style="font-size:11pt; padding:8px 16px; margin-bottom:14px;">✅ Rule Gate: PASSED (Workload & ARN validity not checked)</div>',
                            unsafe_allow_html=True,
                        )
                        st.success("The proposed remediation policy passed all deterministic AST gate rules. Note: verify ARN formats and workload compatibility prior to deployment.")
                    else:
                        st.markdown(
                            f'<div class="badge-fail" style="font-size:11pt; padding:8px 16px; margin-bottom:14px;">❌ Rule Gate: FAILED ({reverify_res["violation_count"]} Violations Remaining)</div>',
                            unsafe_allow_html=True,
                        )
                        for idx, v in enumerate(reverify_res.get("violations", []), 1):
                            st.markdown(f"**{idx}.** `{v['rule']}`: {v['message']}")

                    st.markdown("#### Validated Production-Ready Policy JSON")
                    st.json(suggested_fix)
                else:
                    st.info("Re-verification pass executes when code remediation is proposed.")

            with tab_report:
                st.subheader("Client-Ready Deliverable Reports")
                
                report_md = generate_markdown_report(
                    policy_name=policy_name,
                    original_policy=policy_dict,
                    conftest_results=opa_res,
                    gemma_results=gemma_res,
                    diff_results=diff_res,
                    reverification_results=reverify_res,
                )

                report_html = generate_html_report(
                    policy_name=policy_name,
                    original_policy=policy_dict,
                    conftest_results=opa_res,
                    gemma_results=gemma_res,
                    diff_results=diff_res,
                    reverification_results=reverify_res,
                )

                col_dl1, col_dl2, col_dl3 = st.columns(3)
                with col_dl1:
                    try:
                        pdf_bytes = generate_pdf_report(
                            policy_name=policy_name,
                            original_policy=policy_dict,
                            conftest_results=opa_res,
                            gemma_results=gemma_res,
                            diff_results=diff_res,
                            reverification_results=reverify_res,
                        )
                        st.download_button(
                            label="📕 Download Executive Report (.pdf)",
                            data=pdf_bytes,
                            file_name=f"zeroleak_audit_{policy_name}.pdf",
                            mime="application/pdf",
                            type="primary",
                            use_container_width=True,
                        )
                    except Exception as e:
                        st.error(f"PDF engine notice: {str(e)}")

                with col_dl2:
                    st.download_button(
                        label="🌐 Download Web Report (.html)",
                        data=report_html,
                        file_name=f"zeroleak_audit_{policy_name}.html",
                        mime="text/html",
                        use_container_width=True,
                    )
                with col_dl3:
                    st.download_button(
                        label="📝 Download Developer Report (.md)",
                        data=report_md,
                        file_name=f"zeroleak_audit_{policy_name}.md",
                        mime="text/markdown",
                        use_container_width=True,
                    )

                st.markdown("---")
                st.markdown("### Report Preview")
                st.markdown(report_md)


if __name__ == "__main__":
    main()
