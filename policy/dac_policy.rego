package dac.authz

# Default deny decision object
default decision = {"allow": false, "mode": "deny", "reason": "default deny"}

# ----- Helpers to read risk either by category or numeric score -----
# prefer categorical risk_level if present
risk_level = rl {
    rl := input.context.risk_level
}
risk_level = rl {
    rl := input.risk_level
}

# fallback: derive from numeric risk_score if categorical missing
risk_level = "LOW" {
    not risk_level
    sc := input.context.risk_score
    sc == null
    # if still null, try top-level
    sc := input.risk_score
    sc == null
    # no score available -> conservative HIGH (change if needed)
    false
}
risk_level = "LOW" {
    not risk_level
    sc := input.context.risk_score
    sc != null
    sc <= 30
}
risk_level = "LOW" {
    not risk_level
    sc := input.risk_score
    sc != null
    sc <= 30
}
risk_level = "MEDIUM" {
    not risk_level
    sc := input.context.risk_score
    sc != null
    sc > 30
    sc <= 60
}
risk_level = "MEDIUM" {
    not risk_level
    sc := input.risk_score
    sc != null
    sc > 30
    sc <= 60
}
risk_level = "HIGH" {
    not risk_level
    sc := input.context.risk_score
    sc != null
    sc > 60
}
risk_level = "HIGH" {
    not risk_level
    sc := input.risk_score
    sc != null
    sc > 60
}

# ----- action helper (defaults to "read" if absent) -----
action := a { a := input.action }
action := "read" { not input.action }

# ----- Role/resource helper (customize if needed) -----
allowed_by_role_and_resource {
    # Example: require admin role for admin-prefixed resources
    not (is_admin_resource(input.resource.id) & input.user.role != "admin")
}

is_admin_resource(res) {
    startswith(res, "admin")
}

# ----- Decision rules matching your requested behavior -----
decision = {"allow": true, "mode": "full", "reason": "admin override"} {
    input.user.role == "admin"
}

decision = {"allow": true, "mode": "full", "reason": "policy-low-risk"} {
    risk_level == "LOW"
    allowed_by_role_and_resource
}

decision = {"allow": true, "mode": "read-only", "reason": "policy-medium-risk"} {
    risk_level == "MEDIUM"
    action == "read"
    allowed_by_role_and_resource
}

decision = {"allow": false, "mode": "deny", "reason": "policy-high-risk"} {
    risk_level == "HIGH"
}
