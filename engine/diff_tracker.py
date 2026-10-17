import difflib
import json
from typing import Any, Dict, List, Set, Tuple, Union


def _ensure_dict(policy_input: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(policy_input, dict):
        return policy_input
    if isinstance(policy_input, str):
        return json.loads(policy_input)
    raise ValueError(f"Expected dict or JSON string, got {type(policy_input)}")


def _extract_list(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def _extract_policy_metadata(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts statement-level structure, actions, resources, and special clauses."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    allow_actions: Set[str] = set()
    deny_statements: List[Dict[str, Any]] = []
    has_notaction: bool = False
    has_conditions: bool = False
    resources: Set[str] = set()

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        effect = stmt.get("Effect", "Allow")
        if effect == "Deny":
            deny_statements.append(stmt)

        if "NotAction" in stmt or "NotResource" in stmt:
            has_notaction = True

        if "Condition" in stmt and bool(stmt["Condition"]):
            has_conditions = True

        if effect == "Allow":
            for action in _extract_list(stmt.get("Action", [])):
                allow_actions.add(action.strip())

        for res in _extract_list(stmt.get("Resource", [])):
            resources.add(res.strip())

    return {
        "statement_count": len(statements),
        "allow_actions": allow_actions,
        "resources": resources,
        "deny_statements": deny_statements,
        "has_notaction": has_notaction,
        "has_conditions": has_conditions,
    }


def _matches_action_pattern(pattern: str, action: str) -> bool:
    """Checks if a pattern like '*' or 's3:*' covers a specific action like 's3:GetObject'."""
    pattern_lower = pattern.lower()
    action_lower = action.lower()

    if pattern_lower == "*":
        return True
    if pattern_lower.endswith("*"):
        prefix = pattern_lower[:-1]
        return action_lower.startswith(prefix)
    return pattern_lower == action_lower


def analyze_permission_diff(
    original_input: Union[str, Dict[str, Any]],
    fixed_input: Union[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compares original policy against proposed remediation and classifies permission delta.
    
    Returns structured analysis containing:
      - narrowed: Actions refined from broad wildcards to specific verbs
      - dropped: Actions completely removed (runtime breaker risk)
      - retained: Actions preserved verbatim
      - added: Newly introduced actions not present in original (hallucination risk)
      - guardrails: Flags for Deny changes, NotAction usage, Condition changes
      - human_approval_required: bool
      - warnings: List of warning strings
    """
    try:
        orig = _ensure_dict(original_input)
        fix = _ensure_dict(fixed_input)
    except Exception as e:
        return {
            "error": f"Failed to parse policies for diff analysis: {str(e)}",
            "human_approval_required": True,
            "warnings": [f"Diff parse failure: {str(e)}"],
            "narrowed": [],
            "dropped": [],
            "retained": [],
            "added": [],
            "guardrails": {},
        }

    orig_meta = _extract_policy_metadata(orig)
    fix_meta = _extract_policy_metadata(fix)

    orig_actions = orig_meta["allow_actions"]
    fix_actions = fix_meta["allow_actions"]

    orig_wildcards = {a for a in orig_actions if "*" in a}
    orig_exact = orig_actions - orig_wildcards

    retained: Set[str] = set()
    narrowed: Set[str] = set()
    added: Set[str] = set()
    dropped: Set[str] = set()
    warnings: List[str] = []

    # Check fix actions against original
    for f_act in fix_actions:
        if f_act in orig_exact:
            retained.add(f_act)
        elif any(_matches_action_pattern(w, f_act) for w in orig_wildcards):
            narrowed.add(f_act)
        else:
            # Action was not in original exact list nor covered by original wildcards
            added.add(f_act)

    # Check original actions that disappeared
    for o_act in orig_exact:
        if o_act not in fix_actions:
            dropped.add(o_act)

    # If original had a wildcard like s3:* or *, note that the wildcard itself was replaced
    wildcards_scoped = []
    for w in orig_wildcards:
        if w not in fix_actions:
            wildcards_scoped.append(w)

    if wildcards_scoped:
        warnings.append(
            f"WILDCARD NARROWING: Unrestricted wildcard(s) {', '.join(sorted(wildcards_scoped))} were scoped to {len(narrowed)} specific verb(s). "
            f"All other implicit API actions in these namespaces were removed."
        )

    # Guardrails: Deny statements
    deny_dropped = len(orig_meta["deny_statements"]) > len(fix_meta["deny_statements"])
    if deny_dropped:
        warnings.append(
            "CRITICAL: Proposed fix removed one or more 'Deny' statements. "
            "Dropping a Deny is a severe privilege escalation risk!"
        )

    # Guardrails: NotAction
    notaction_flagged = orig_meta["has_notaction"] or fix_meta["has_notaction"]
    if notaction_flagged:
        warnings.append(
            "SCOPE LIMIT: Policy uses 'NotAction'. Dropping or modifying NotAction "
            "requires manual human review."
        )

    # Guardrails: Conditions
    if orig_meta["has_conditions"] and not fix_meta["has_conditions"]:
        warnings.append(
            "WARNING: Original policy had 'Condition' blocks which are missing in the proposed fix."
        )

    # Runtime breaker warning
    if dropped:
        warnings.append(
            f"Human approval required: {len(dropped)} specific action(s) were dropped ({', '.join(sorted(dropped)[:5])}). "
            "Review dropped permissions to prevent breaking application runtime."
        )

    if added:
        warnings.append(
            f"POTENTIAL HALLUCINATION: Proposed fix added {len(added)} action(s) not present in original: "
            f"{', '.join(sorted(added))}."
        )

    # Guardrails: Principal alteration in Trust Policies
    orig_principals = []
    for stmt in orig.get("Statement", []) if isinstance(orig.get("Statement"), list) else [orig.get("Statement", {})]:
        if isinstance(stmt, dict) and "Principal" in stmt:
            orig_principals.append(stmt["Principal"])

    fix_principals = []
    for stmt in fix.get("Statement", []) if isinstance(fix.get("Statement"), list) else [fix.get("Statement", {})]:
        if isinstance(stmt, dict) and "Principal" in stmt:
            fix_principals.append(stmt["Principal"])

    principal_altered = bool(orig_principals and orig_principals != fix_principals)
    if principal_altered:
        warnings.append(
            "RUNTIME BREAKER RISK: Proposed remediation altered or replaced the 'Principal' block. "
            "Changing service principals (e.g. 'lambda.amazonaws.com') will prevent AWS services from assuming this role!"
        )

    human_approval_required = bool(dropped or added or deny_dropped or notaction_flagged or principal_altered)

    return {
        "error": None,
        "human_approval_required": human_approval_required,
        "retained": sorted(list(retained)),
        "narrowed": sorted(list(narrowed)),
        "wildcards_scoped": sorted(wildcards_scoped),
        "dropped": sorted(list(dropped)),
        "added": sorted(list(added)),
        "warnings": warnings,
        "guardrails": {
            "deny_dropped": deny_dropped,
            "notaction_flagged": notaction_flagged,
            "conditions_missing": orig_meta["has_conditions"] and not fix_meta["has_conditions"],
        },
    }


def generate_unified_diff(
    original_input: Union[str, Dict[str, Any]],
    fixed_input: Union[str, Dict[str, Any]],
) -> str:
    """Generates standard unified diff lines between original and fixed policy JSONs."""
    try:
        orig_dict = _ensure_dict(original_input)
        fix_dict = _ensure_dict(fixed_input)
        orig_str = json.dumps(orig_dict, indent=2).splitlines(keepends=True)
        fix_str = json.dumps(fix_dict, indent=2).splitlines(keepends=True)

        diff = difflib.unified_diff(
            orig_str,
            fix_str,
            fromfile="Original Policy (Vulnerable)",
            tofile="Proposed Remediation (Scoped)",
            n=3,
        )
        return "".join(diff)
    except Exception as e:
        return f"Error generating diff: {str(e)}"


if __name__ == "__main__":
    orig_example = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3FullAccess",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
            },
            {
                "Sid": "DynamoDBRead",
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
                "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/AppTable",
            },
        ],
    }

    fixed_example = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3ScopedAccess",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-secure-bucket/*",
            },
            {
                "Sid": "DynamoDBRead",
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem"],
                "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/AppTable",
            },
        ],
    }

    diff_result = analyze_permission_diff(orig_example, fixed_example)
    print("Diff Analysis Result:")
    print(json.dumps(diff_result, indent=2))
    print("\nUnified Diff:")
    print(generate_unified_diff(orig_example, fixed_example))
