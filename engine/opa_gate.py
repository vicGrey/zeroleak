import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Union

DEFAULT_REGO_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "policies", "iam_policy.rego")
)


def get_conftest_executable() -> str:
    """Find conftest executable on PATH or fallback to /usr/local/bin/conftest."""
    conftest_path = shutil.which("conftest")
    if conftest_path:
        return conftest_path
    if os.path.exists("/usr/local/bin/conftest"):
        return "/usr/local/bin/conftest"
    raise FileNotFoundError("Conftest executable not found on system.")


def evaluate_policy(
    policy_input: Union[str, Dict[str, Any]],
    policy_rego_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluates an AWS IAM Policy against deterministic Rego rules using Conftest.
    
    Args:
        policy_input: Raw JSON string or parsed dict representing an IAM policy.
        policy_rego_path: Absolute or relative path to the rego file. Defaults to policies/iam_policy.rego.
        
    Returns:
        Dict containing:
            - valid_json (bool)
            - passed (bool)
            - violations (List[Dict[str, str]])
            - violation_count (int)
            - error (Optional[str])
            - raw_output (Any)
    """
    rego_path = policy_rego_path or DEFAULT_REGO_PATH
    if not os.path.exists(rego_path):
        return {
            "valid_json": True,
            "passed": False,
            "violations": [],
            "violation_count": 0,
            "error": f"Rego policy file not found at: {rego_path}",
            "raw_output": None,
        }

    # Normalize policy input to JSON string
    if isinstance(policy_input, dict):
        try:
            policy_json_str = json.dumps(policy_input, indent=2)
            parsed_policy = policy_input
        except Exception as e:
            return {
                "valid_json": False,
                "passed": False,
                "violations": [],
                "violation_count": 0,
                "error": f"Failed to serialize policy dict: {str(e)}",
                "raw_output": None,
            }
    elif isinstance(policy_input, str):
        policy_json_str = policy_input.strip()
        try:
            parsed_policy = json.loads(policy_json_str)
        except json.JSONDecodeError as e:
            return {
                "valid_json": False,
                "passed": False,
                "violations": [],
                "violation_count": 0,
                "error": f"Malformed IAM Policy JSON: {str(e)}",
                "raw_output": None,
            }
    else:
        return {
            "valid_json": False,
            "passed": False,
            "violations": [],
            "violation_count": 0,
            "error": f"Unsupported policy input type: {type(policy_input)}",
            "raw_output": None,
        }

    try:
        conftest_bin = get_conftest_executable()
        cmd = [conftest_bin, "test", "--output", "json", "-p", rego_path, "-"]
        process = subprocess.run(
            cmd,
            input=policy_json_str,
            text=True,
            capture_output=True,
            check=False,
        )

        stdout = process.stdout.strip()
        stderr = process.stderr.strip()

        if not stdout:
            if process.returncode != 0:
                return {
                    "valid_json": True,
                    "passed": False,
                    "violations": [],
                    "violation_count": 0,
                    "error": f"Conftest execution failed (code {process.returncode}): {stderr}",
                    "raw_output": stderr,
                }
            # Conftest exited 0 with no output (all passed)
            return {
                "valid_json": True,
                "passed": True,
                "violations": [],
                "violation_count": 0,
                "error": None,
                "raw_output": [],
            }

        conftest_json = json.loads(stdout)
        violations: List[Dict[str, str]] = []

        # Parse conftest JSON array
        # Format: [{"filename": "-", "namespace": "main", "successes": 1, "failures": [{"msg": "..."}]}]
        for entry in conftest_json:
            failures = entry.get("failures", [])
            for fail in failures:
                msg = fail.get("msg", "")
                rule_match = re.search(r"\[Rule:\s*([^\]]+)\]", msg)
                rule_id = rule_match.group(1).strip() if rule_match else "unknown_rule"
                violations.append({
                    "rule": rule_id,
                    "message": msg,
                })

        passed = len(violations) == 0 and process.returncode == 0

        return {
            "valid_json": True,
            "passed": passed,
            "violations": violations,
            "violation_count": len(violations),
            "error": None,
            "raw_output": conftest_json,
        }

    except Exception as e:
        return {
            "valid_json": True,
            "passed": False,
            "violations": [],
            "violation_count": 0,
            "error": f"OPA/Conftest runner exception: {str(e)}",
            "raw_output": None,
        }


if __name__ == "__main__":
    # Self-test
    test_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TestStatement",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    result = evaluate_policy(test_policy)
    print("Self-Test Result:")
    print(json.dumps(result, indent=2))
