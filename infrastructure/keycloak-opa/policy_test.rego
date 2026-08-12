package agent_authz_test

import data.agent_authz.allow

valid_input := {
    "token_active": true,
    "human_id": "human-e001",
    "agent_id": "agent-e001",
    "delegation_id": "delegation-e001",
    "roles": ["payments_preview"],
    "resource": "payments",
    "action": "preview",
}

test_valid_preview_is_allowed if {
    allow with input as valid_input
}

test_execute_is_denied if {
    not allow with input as object.union(valid_input, {"action": "execute"})
}

test_inactive_token_is_denied if {
    not allow with input as object.union(valid_input, {"token_active": false})
}

test_missing_human_is_denied if {
    not allow with input as object.union(valid_input, {"human_id": ""})
}

test_missing_agent_is_denied if {
    not allow with input as object.union(valid_input, {"agent_id": ""})
}

test_missing_delegation_is_denied if {
    not allow with input as object.union(valid_input, {"delegation_id": ""})
}

test_missing_preview_role_is_denied if {
    not allow with input as object.union(valid_input, {"roles": []})
}

test_execute_role_does_not_authorize_execute if {
    not allow with input as object.union(valid_input, {
        "action": "execute",
        "roles": ["payments_preview", "payments_execute"],
    })
}
