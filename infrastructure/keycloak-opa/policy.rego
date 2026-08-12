package agent_authz

default allow := false

allow if {
    input.token_active == true
    input.human_id != ""
    input.agent_id != ""
    input.delegation_id != ""
    input.resource == "payments"
    input.action == "preview"
    "payments_preview" in input.roles
}

decision := {
    "allow": allow,
    "human_id": input.human_id,
    "agent_id": input.agent_id,
    "delegation_id": input.delegation_id,
    "resource": input.resource,
    "action": input.action,
    "token_active": input.token_active,
    "policy_revision": "e001-v1"
}
