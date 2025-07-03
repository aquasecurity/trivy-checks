# METADATA
# title: SAM State machine must have logging enabled
# description: |
#   Logging enables end-to-end debugging and analysis of all state machine activities.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-logging
# custom:
#   id: AWS-0119
#   aliases:
#     - AVD-AWS-0119
#     - enable-state-machine-logging
#   long_id: aws-sam-enable-state-machine-logging
#   provider: aws
#   service: sam
#   severity: LOW
#   recommended_action: Enable logging
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   examples: checks/cloud/aws/sam/enable_state_machine_logging.yaml
package builtin.aws.sam.aws0119

import rego.v1

deny contains res if {
	some state_machine in input.aws.sam.statemachines
	isManaged(state_machine)
	not state_machine.loggingconfiguration.loggingenabled.value
	res := result.new(
		"Logging is not enabled",
		state_machine.loggingconfiguration.loggingenabled,
	)
}
