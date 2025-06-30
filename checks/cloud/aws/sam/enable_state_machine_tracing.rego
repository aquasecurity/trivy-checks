# METADATA
# title: SAM State machine must have X-Ray tracing enabled
# description: |
#   X-Ray tracing enables end-to-end debugging and analysis of all state machine activities.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-tracing
# custom:
#   id: AVD-AWS-0117
#   avd_id: AVD-AWS-0117
#   provider: aws
#   service: sam
#   severity: LOW
#   short_code: enable-state-machine-tracing
#   recommended_action: Enable tracing
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   examples: checks/cloud/aws/sam/enable_state_machine_tracing.yaml
package builtin.aws.sam.aws0117

import rego.v1

deny contains res if {
	some state_machine in input.aws.sam.statemachines
	isManaged(state_machine)

	not state_machine.tracing.enabled.value
	res := result.new(
		"X-Ray tracing is not enabled",
		state_machine.tracing.enabled,
	)
}
