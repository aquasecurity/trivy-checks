# METADATA
# title: Athena workgroups should enforce configuration to prevent client disabling encryption
# description: |
#   Clients can ignore encryption requirements without enforced configuration. Athena workgroup configuration should be enforced to prevent client side changes to disable encryption settings.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html
# custom:
#   id: AWS-0007
#   aliases:
#     - AVD-AWS-0007
#     - no-encryption-override
#   long_id: aws-athena-no-encryption-override
#   provider: aws
#   service: athena
#   severity: HIGH
#   recommended_action: Enforce the configuration to prevent client overrides
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: athena
#             provider: aws
#   examples: checks/cloud/aws/athena/no_encryption_override.yaml
package builtin.aws.athena.aws0007

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some workgroup in input.aws.athena.workgroups
	not workgroup.enforceconfiguration.value
	res := result.new(
		"The workgroup configuration is not enforced.",
		metadata.obj_by_path(workgroup, ["enforceconfiguration"]),
	)
}
