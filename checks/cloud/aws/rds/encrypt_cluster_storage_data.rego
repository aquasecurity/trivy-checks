# METADATA
# title: There is no encryption specified or encryption is disabled on the RDS Cluster.
# description: |
#   Encryption should be enabled for an RDS Aurora cluster.
#   When enabling encryption by setting the kms_key_id, the storage_encrypted must also be set to true.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html
# custom:
#   id: AVD-AWS-0079
#   avd_id: AVD-AWS-0079
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: encrypt-cluster-storage-data
#   recommended_action: Enable encryption for RDS clusters
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster
#     good_examples: checks/cloud/aws/rds/encrypt_cluster_storage_data.tf.go
#     bad_examples: checks/cloud/aws/rds/encrypt_cluster_storage_data.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/rds/encrypt_cluster_storage_data.cf.go
#     bad_examples: checks/cloud/aws/rds/encrypt_cluster_storage_data.cf.go
package builtin.aws.rds.aws0079

import rego.v1

deny contains res if {
	some cluster in input.aws.rds.clusters
	isManaged(cluster)
	not encryption_enabled(cluster)
	res := result.new(
		"Cluster does not have storage encryption enabled.",
		object.get(cluster.encryption, "encryptstorage", cluster.encryption),
	)
}

deny contains res if {
	some cluster in input.aws.rds.clusters
	isManaged(cluster)
	encryption_enabled(cluster)
	not has_kms_key(cluster)
	res := result.new(
		"Cluster does not specify a customer managed key for storage encryption.",
		object.get(cluster.encryption, "kmskeyid", cluster.encryption),
	)
}

encryption_enabled(cluster) := cluster.encryption.encryptstorage.value

has_kms_key(cluster) := cluster.encryption.kmskeyid.value != ""
