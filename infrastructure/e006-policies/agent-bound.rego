package e006

# relation-aware, plus the binding it was missing.
#
# The organization is taken from the grant, not from the caller, so this inherits
# the Amendment 1 property. It additionally requires that the agent presenting the
# delegation is the agent the delegation was issued to.
#
# Without that last line, a delegation is a bearer credential: any agent that
# knows a delegation id inherits its authority, and every other check still reads
# green because agent_id is present in the input and is evaluated.

default allow := false

allow if {
    input.token_active == true
    input.agent_id != ""
    input.delegation_id != ""
    input.agent_id == input.delegation_agent
    input.action == "documents:read"
    "documents_read" in input.roles
    input.resource_org != ""
    input.resource_org == input.grant_org
}

decision := {
    "allow": allow,
    "evaluated": ["token_active", "agent_id", "delegation_id", "delegation_agent", "action", "roles", "resource_org", "grant_org"],
    "resource_org_consulted": true,
    "resource_org": input.resource_org,
    "grant_org": input.grant_org,
    "asserted_org": input.asserted_org,
    "delegation_agent": input.delegation_agent,
    "agent_bound": input.agent_id == input.delegation_agent,
    "relation_source": "grant",
    "policy_revision": "e006-agent-bound",
}
