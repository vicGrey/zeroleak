import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def is_terraform_plan(data: Any) -> bool:
    """Determines whether a parsed JSON object is a Terraform plan output."""
    if not isinstance(data, dict):
        return False
    return "resource_changes" in data or ("format_version" in data and "terraform_version" in data)


def extract_iam_policies_from_plan(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Scans a Terraform plan JSON and extracts all embedded IAM policies from resource_changes.
    Supports inline role policies, managed policies, bucket policies, and assume_role_policies.
    Also surfaces policies whose text is computed at apply time (known after apply).
    
    Returns a list of dicts:
        - address: Full terraform address (e.g., module.api_gateway.aws_iam_role_policy.api_gateway_cloudwatch)
        - resource_type: Resource type (e.g., aws_iam_role_policy)
        - resource_name: Logical resource name
        - attribute: Attribute where policy was defined (e.g., 'policy', 'assume_role_policy')
        - policy_dict: Parsed IAM Policy JSON object (or None if unknown at plan time)
        - policy_json_str: Formatted JSON string
        - statement_count: Number of statements in the policy
        - is_evaluated: bool (True if policy text was available for audit)
        - unevaluated_reason: Optional explanation if policy text was unknown at plan time
    """
    if not is_terraform_plan(data):
        return []

    extracted: List[Dict[str, Any]] = []
    seen_addresses = set()

    for r in data.get("resource_changes", []):
        address = r.get("address", r.get("name", "unknown_resource"))
        resource_type = r.get("type", "")
        resource_name = r.get("name", "")

        after = r.get("change", {}).get("after")
        if not isinstance(after, dict):
            continue

        # 1. Look for standard IAM policy attributes with readable JSON text
        target_attrs = ["policy", "assume_role_policy"]
        for attr in target_attrs:
            pol_raw = after.get(attr)
            if not pol_raw:
                continue

            pol_dict = None
            if isinstance(pol_raw, str):
                try:
                    pol_dict = json.loads(pol_raw)
                except Exception:
                    continue
            elif isinstance(pol_raw, dict):
                pol_dict = pol_raw

            if isinstance(pol_dict, dict) and "Statement" in pol_dict:
                unique_key = f"{address}:{attr}"
                if unique_key in seen_addresses:
                    continue
                seen_addresses.add(unique_key)

                statements = pol_dict.get("Statement", [])
                extracted.append({
                    "address": address,
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "attribute": attr,
                    "policy_dict": pol_dict,
                    "policy_json_str": json.dumps(pol_dict, indent=2),
                    "statement_count": len(statements) if isinstance(statements, list) else 1,
                    "is_evaluated": True,
                    "unevaluated_reason": None,
                })

        # 2. Capture IAM and bucket policies whose policy document is unknown/computed at plan time
        after_unknown = r.get("change", {}).get("after_unknown") or {}
        if resource_type in [
            "aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy", 
            "aws_iam_group_policy", "aws_s3_bucket_policy"
        ]:
            if after_unknown.get("policy") or not after.get("policy"):
                unique_key = f"{address}:policy"
                if unique_key not in seen_addresses:
                    seen_addresses.add(unique_key)
                    extracted.append({
                        "address": address,
                        "resource_type": resource_type,
                        "resource_name": resource_name,
                        "attribute": "policy",
                        "policy_dict": None,
                        "policy_json_str": "",
                        "statement_count": 0,
                        "is_evaluated": False,
                        "unevaluated_reason": "Policy text unknown at plan time (computed after apply)",
                    })

    return extracted
