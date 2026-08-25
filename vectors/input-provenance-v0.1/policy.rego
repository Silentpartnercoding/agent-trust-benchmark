package atb.input_provenance

default allow := false

allow if {
    input.action_type == "documents.read"
    input.resource_organization == input.organization
    input.agent_id == input.delegation_agent
    input.kill_switch == false
}
