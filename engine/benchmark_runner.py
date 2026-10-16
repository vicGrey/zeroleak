import glob
import json
import os
import sys
from typing import Any, Dict, List

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.diff_tracker import analyze_permission_diff
from engine.gemma_analyzer import analyze_with_gemma, check_ollama_status
from engine.opa_gate import evaluate_policy

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples", "policies"))
RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples", "results"))


def run_single_benchmark(policy_path: str, run_gemma: bool = True) -> Dict[str, Any]:
    """Runs a full audit benchmark for a single policy file and logs raw data."""
    base_name = os.path.basename(policy_path)
    with open(policy_path, "r", encoding="utf-8") as f:
        policy_dict = json.load(f)

    # 1. OPA / Conftest alone
    opa_result = evaluate_policy(policy_dict)

    # 2. Gemma 2B alone
    gemma_result: Dict[str, Any] = {}
    diff_result: Dict[str, Any] = {}
    reverify_result: Dict[str, Any] = {}

    if run_gemma:
        gemma_result = analyze_with_gemma(policy_dict)
        suggested_fix = gemma_result.get("suggested_fix")

        if suggested_fix:
            # Stage 3: Guardrail diff
            diff_result = analyze_permission_diff(policy_dict, suggested_fix)
            # Stage 3: Automated Conftest re-verification
            reverify_result = evaluate_policy(suggested_fix)

    benchmark_entry = {
        "policy_file": base_name,
        "input_policy": policy_dict,
        "opa_alone": {
            "passed": opa_result.get("passed", False),
            "violation_count": opa_result.get("violation_count", 0),
            "violations": opa_result.get("violations", []),
        },
        "gemma_alone": {
            "success": gemma_result.get("success", False),
            "latency_seconds": gemma_result.get("latency_seconds"),
            "threat_explanation": gemma_result.get("threat_explanation"),
            "combination_risks": gemma_result.get("combination_risks", []),
            "has_suggested_fix": bool(gemma_result.get("suggested_fix")),
            "error": gemma_result.get("error"),
        },
        "zeroleak_combined": {
            "initial_opa_passed": opa_result.get("passed", False),
            "gemma_caught_risks": bool(gemma_result.get("combination_risks")),
            "reverification_passed": reverify_result.get("passed", False) if reverify_result else None,
            "reverification_violations": reverify_result.get("violation_count", 0) if reverify_result else None,
            "permission_loss": {
                "narrowed": diff_result.get("narrowed", []),
                "dropped": diff_result.get("dropped", []),
                "retained": diff_result.get("retained", []),
                "added": diff_result.get("added", []),
                "warnings": diff_result.get("warnings", []),
            } if diff_result else {},
        },
    }

    # Save raw output log
    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_file = os.path.join(RESULTS_DIR, base_name)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(benchmark_entry, f, indent=2)

    return benchmark_entry


def run_all_benchmarks(run_gemma: bool = True) -> List[Dict[str, Any]]:
    """Runs benchmarks across all sample policies."""
    files = sorted(glob.glob(os.path.join(SAMPLES_DIR, "*.json")))
    results = []
    print(f"Executing ZeroLeak Benchmark on {len(files)} test policies...")

    for fpath in files:
        bname = os.path.basename(fpath)
        print(f" -> Testing {bname}...")
        entry = run_single_benchmark(fpath, run_gemma=run_gemma)
        results.append(entry)

    print(f"Benchmark run complete. Raw outputs saved to: {RESULTS_DIR}")
    return results


if __name__ == "__main__":
    status = check_ollama_status()
    should_run_gemma = status["online"] and status["has_gemma2_2b"]
    if not should_run_gemma:
        print("Note: Ollama / Gemma 2B not detected online. Running OPA-only benchmark pass...")
    run_all_benchmarks(run_gemma=should_run_gemma)
