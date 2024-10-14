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
#   id: AVD-AWS-0007
#   avd_id: AVD-AWS-0007
#   provider: aws
#   service: athena
#   severity: HIGH
#   short_code: no-encryption-override
#   recommended_action: Enforce the configuration to prevent client overrides
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: athena
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#configuration
#     good_examples: checks/cloud/aws/athena/no_encryption_override.yaml
#     bad_examples: checks/cloud/aws/athena/no_encryption_override.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/athena/no_encryption_override.yaml
#     bad_examples: checks/cloud/aws/athena/no_encryption_override.yaml
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
