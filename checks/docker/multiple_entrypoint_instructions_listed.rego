# METADATA
# title: "Multiple ENTRYPOINT instructions listed"
# description: "There can only be one ENTRYPOINT instruction in a Dockerfile. Only the last ENTRYPOINT instruction in the Dockerfile will have an effect."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://docs.docker.com/engine/reference/builder/#entrypoint
# custom:
#   id: DS-0007
#   aliases:
#     - AVD-DS-0007
#     - DS007
#     - only-one-entrypoint
#   long_id: docker-only-one-entrypoint
#   severity: CRITICAL
#   recommended_action: "Remove unnecessary ENTRYPOINT instruction."
#   input:
#     selector:
#       - type: dockerfile
#   examples: checks/docker/multiple_entrypoint_instructions_listed.yaml
package builtin.dockerfile.DS007

import rego.v1

import data.lib.docker

deny contains res if {
	entrypoints := docker.stage_entrypoints[stage]
	count(entrypoints) > 1
	msg := sprintf("There are %d duplicate ENTRYPOINT instructions", [count(entrypoints)])
	res := result.new(msg, entrypoints[1])
}
