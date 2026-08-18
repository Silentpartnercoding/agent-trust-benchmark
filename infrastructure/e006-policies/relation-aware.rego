package e006

# Relation-scoped authorization. The grant names an action AND an organization.
# The decision requires the requested resource to belong to that organization.
#
# The identifier is not sufficient on its own: substituting another document's
# identifier changes input.resource_org and the decision flips to deny.

default allow := false

allow if {
    input.token_active == true
    input.agent_id != ""
    input.delegation_id != ""
    input.action == "documents:read"
    "documents_read" in input.roles
    input.resource_org != ""
    input.resource_org == input.grant_org
}

decision := {
    "allow": allow,
    "evaluated": ["token_active", "agent_id", "delegation_id", "action", "roles", "resource_org", "grant_org"],
    "resource_org_consulted": true,
    "resource_org": input.resource_org,
    "grant_org": input.grant_org,
    "policy_revision": "e006-relation-aware",
}
