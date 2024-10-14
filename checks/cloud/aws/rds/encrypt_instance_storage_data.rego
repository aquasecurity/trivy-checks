# METADATA
# title: RDS encryption has not been enabled at a DB Instance level.
# description: |
#   Encryption should be enabled for an RDS Database instances.
#   When enabling encryption by setting the kms_key_id.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html
# custom:
#   id: AVD-AWS-0080
#   avd_id: AVD-AWS-0080
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: encrypt-instance-storage-data
#   recommended_action: Enable encryption for RDS instances
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance
#     good_examples: checks/cloud/aws/rds/encrypt_instance_storage_data.yaml
#     bad_examples: checks/cloud/aws/rds/encrypt_instance_storage_data.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/rds/encrypt_instance_storage_data.yaml
#     bad_examples: checks/cloud/aws/rds/encrypt_instance_storage_data.yaml
package builtin.aws.rds.aws0080

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some instance in input.aws.rds.instances
	without_replication_source_arn(instance)
	encryption_disabled(instance)
	res := result.new(
		"Instance does not have storage encryption enabled.",
		metadata.obj_by_path(instance, ["encryption", "encryptstorage"]),
	)
}

without_replication_source_arn(instance) if value.is_empty(instance.replciationsourcearn)

without_replication_source_arn(instance) if not instance.replciationsourcearn

encryption_disabled(instance) if value.is_false(instance.encryption.encryptstorage)

encryption_disabled(instance) if not instance.encryption.encryptstorage
