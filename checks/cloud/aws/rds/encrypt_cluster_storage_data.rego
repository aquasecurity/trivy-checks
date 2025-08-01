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
#   id: AWS-0079
#   aliases:
#     - AVD-AWS-0079
#     - encrypt-cluster-storage-data
#   long_id: aws-rds-encrypt-cluster-storage-data
#   provider: aws
#   service: rds
#   severity: HIGH
#   recommended_action: Enable encryption for RDS clusters
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
#   examples: checks/cloud/aws/rds/encrypt_cluster_storage_data.yaml
package builtin.aws.rds.aws0079

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.rds.clusters
	isManaged(cluster)
	encryption_disabled(cluster)
	res := result.new(
		"Cluster does not have storage encryption enabled.",
		metadata.obj_by_path(cluster, ["encryption", "encryptstorage"]),
	)
}

deny contains res if {
	some cluster in input.aws.rds.clusters
	isManaged(cluster)
	cluster.encryption.encryptstorage.value
	without_cmk(cluster)
	res := result.new(
		"Cluster does not specify a customer managed key for storage encryption.",
		metadata.obj_by_path(cluster, ["encryption", "kmskeyid"]),
	)
}

encryption_disabled(cluster) if value.is_false(cluster.encryption.encryptstorage)

encryption_disabled(cluster) if not cluster.encryption.encryptstorage

without_cmk(cluster) if value.is_empty(cluster.encryption.kmskeyid)

without_cmk(cluster) if not cluster.encryption.kmskeyid
