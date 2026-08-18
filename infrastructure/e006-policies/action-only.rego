package e006

# Action-type authorization. The grant names an action; the decision checks that
# the action was granted. The resource's organization is never consulted.
#
# This is the shape that produces cross-tenant IDOR: every record reads in-scope
# because the action WAS granted. The predicate simply never bound the resource.

default allow := false

allow if {
    input.token_active == true
    input.agent_id != ""
    input.delegation_id != ""
    input.action == "documents:read"
    "documents_read" in input.roles
}

decision := {
    "allow": allow,
    "evaluated": ["token_active", "agent_id", "delegation_id", "action", "roles"],
    "resource_org_consulted": false,
    "policy_revision": "e006-action-only",
}
