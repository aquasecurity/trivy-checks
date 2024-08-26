# METADATA
# title: ECS Task Definitions with EFS volumes should use in-transit encryption
# description: |
#   ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html
#   - https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html
# custom:
#   id: AVD-AWS-0035
#   avd_id: AVD-AWS-0035
#   provider: aws
#   service: ecs
#   severity: HIGH
#   short_code: enable-in-transit-encryption
#   recommended_action: Enable in transit encryption when using efs
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ecs
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#transit_encryption
#     good_examples: checks/cloud/aws/ecs/enable_in_transit_encryption.tf.go
#     bad_examples: checks/cloud/aws/ecs/enable_in_transit_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ecs/enable_in_transit_encryption.cf.go
#     bad_examples: checks/cloud/aws/ecs/enable_in_transit_encryption.cf.go
package builtin.aws.ecs.aws0035

import rego.v1

deny contains res if {
	some task_definition in input.aws.ecs.taskdefinitions
	some volume in task_definition.volumes
	volume.efsvolumeconfiguration.transitencryptionenabled.value == false
	res := result.new(
		"Task definition includes a volume which does not have in-transit-encryption enabled.",
		volume.efsvolumeconfiguration.transitencryptionenabled,
	)
}
