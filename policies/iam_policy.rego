package main
import rego.v1

# -----------------------------------------------------------------------------
# ZeroLeak AI — Deterministic Policy Gate
# Ported and expanded from Victor Okoroafor's AWS Serverless Zero-Trust Governance FYP
# Repo: https://github.com/vicGrey/aws-serverless-zero-trust-governance
# -----------------------------------------------------------------------------

# Helper to check if an Action field contains a wildcard (* or service:*)
has_wildcard_action(field) if {
    is_string(field)
    contains(field, "*")
}
has_wildcard_action(field) if {
    is_array(field)
    contains(field[_], "*")
}

# Helper to check if a statement permits a specific action
has_action(stmt, action) if {
    is_string(stmt.Action)
    stmt.Action == action
}
has_action(stmt, action) if {
    is_array(stmt.Action)
    stmt.Action[_] == action
}

# Helper to check if a Resource field permits unrestricted wildcard ('*' or global ARN wildcards)
has_wildcard_resource(field) if {
    is_string(field)
    field == "*"
}
has_wildcard_resource(field) if {
    is_array(field)
    field[_] == "*"
}
# Flag unconstrained S3 bucket wildcards: arn:aws:s3:::* or arn:aws:s3:::*/*
has_wildcard_resource(field) if {
    is_string(field)
    field == "arn:aws:s3:::*"
}
has_wildcard_resource(field) if {
    is_string(field)
    field == "arn:aws:s3:::*/*"
}
has_wildcard_resource(field) if {
    is_array(field)
    field[_] == "arn:aws:s3:::*"
}
has_wildcard_resource(field) if {
    is_array(field)
    field[_] == "arn:aws:s3:::*/*"
}
# Flag global all-service wildcard ARNs: arn:aws:*:*:*:*
has_wildcard_resource(field) if {
    is_string(field)
    field == "arn:aws:*:*:*:*"
}
has_wildcard_resource(field) if {
    is_array(field)
    field[_] == "arn:aws:*:*:*:*"
}

# Helper to safely retrieve Sid or fallback to 'Unassigned'
get_sid(stmt) := stmt.Sid if {
    stmt.Sid != ""
} else := "Unassigned"

# Helper to describe action for display and message differentiation
get_actions(stmt) := desc if {
    is_string(stmt.Action)
    desc := stmt.Action
} else := desc if {
    is_array(stmt.Action)
    count(stmt.Action) <= 2
    desc := concat(", ", stmt.Action)
} else := desc if {
    is_array(stmt.Action)
    count(stmt.Action) > 2
    desc := sprintf("%s, ... (+%d more)", [concat(", ", [stmt.Action[0], stmt.Action[1]]), count(stmt.Action) - 2])
} else := "unspecified"

# Helper to extract statements from either raw IAM Policy JSON or Terraform plan JSON
get_statements contains stmt if {
    stmt := input.Statement[_]
}
get_statements contains stmt if {
    some resource in input.resource_changes
    policy := json.unmarshal(resource.change.after.policy)
    stmt := policy.Statement[_]
}

# Rule 1: Deny wildcard Action '*' in Allow statements
deny contains msg if {
    some stmt in get_statements
    stmt.Effect == "Allow"
    has_wildcard_action(stmt.Action)
    msg := sprintf("[Rule: no_wildcard_action] Statement (Sid: '%s', Action: '%s') permits wildcard (*) Action. Over-privileged access violates least privilege.", [get_sid(stmt), get_actions(stmt)])
}

# Rule 2: Deny wildcard Resource '*' in Allow statements
deny contains msg if {
    some stmt in get_statements
    stmt.Effect == "Allow"
    has_wildcard_resource(stmt.Resource)
    msg := sprintf("[Rule: no_wildcard_resource] Statement (Sid: '%s', Action: '%s') permits unrestricted Resource ('*'). Resources must be explicitly scoped by ARN.", [get_sid(stmt), get_actions(stmt)])
}

# Rule 3: Deny dangerous NotAction paired with Effect: Allow
deny contains msg if {
    some stmt in get_statements
    stmt.Effect == "Allow"
    stmt.NotAction != ""
    msg := sprintf("[Rule: no_notaction_allow] Statement (Sid: '%s') uses 'NotAction' with 'Effect: Allow'. This grants all AWS actions except the excluded list, creating massive privilege escalation risk.", [get_sid(stmt)])
}

# Rule 4: Deny PassRole paired with lambda:CreateFunction (Privilege Escalation Discovery Loop)
deny contains msg if {
    some s1 in get_statements
    s1.Effect == "Allow"
    has_action(s1, "iam:PassRole")
    some s2 in get_statements
    s2.Effect == "Allow"
    has_action(s2, "lambda:CreateFunction")
    msg := "[Rule: passrole_lambda_escalation] PassRole paired with lambda:CreateFunction allows privilege escalation via role assumption."
}
