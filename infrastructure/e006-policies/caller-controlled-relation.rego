package e006

# Relation-scoped authorization where the organization compared against is taken
# from the request rather than from the grant.
#
# This is identical to relation-aware in every respect that E006's original five
# checks can observe. The relation is present in the decision input, it is
# genuinely evaluated, and substituting the resource identifier changes
# input.resource_org and flips the decision.
#
# The difference is input.asserted_org. An honest caller sends the organization
# they belong to and the decision is indistinguishable from relation-aware. A
# caller who sends the target's organization is compared against their own
# assertion, and the boundary is crossed with the relation still evaluated.
#
# The grant's own organization, input.grant_org, is never consulted.

default allow := false

allow if {
    input.token_active == true
    input.agent_id != ""
    input.delegation_id != ""
    input.action == "documents:read"
    "documents_read" in input.roles
    input.resource_org != ""
    input.resource_org == input.asserted_org
}

decision := {
    "allow": allow,
    "evaluated": ["token_active", "agent_id", "delegation_id", "action", "roles", "resource_org", "asserted_org"],
    "resource_org_consulted": true,
    "resource_org": input.resource_org,
    "grant_org": input.grant_org,
    "asserted_org": input.asserted_org,
    "relation_source": "request",
    "policy_revision": "e006-caller-controlled-relation",
}
