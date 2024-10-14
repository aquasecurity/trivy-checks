# METADATA
# title: Redshift clusters should use at rest encryption
# description: |
#   Redshift clusters that contain sensitive data or are subject to regulation should be encrypted at rest to prevent data leakage should the infrastructure be compromised.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html
# custom:
#   id: AVD-AWS-0084
#   avd_id: AVD-AWS-0084
#   provider: aws
#   service: redshift
#   severity: HIGH
#   short_code: encryption-customer-key
#   recommended_action: Enable encryption using CMK
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: redshift
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#encrypted
#     good_examples: checks/cloud/aws/redshift/encryption_customer_key.yaml
#     bad_examples: checks/cloud/aws/redshift/encryption_customer_key.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/redshift/encryption_customer_key.yaml
#     bad_examples: checks/cloud/aws/redshift/encryption_customer_key.yaml
package builtin.aws.redshift.aws0084

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.redshift.clusters
	is_not_encrypted(cluster)
	res := result.new(
		"Cluster does not have encryption enabled.",
		cluster.encryption,
	)
}

deny contains res if {
	some cluster in input.aws.redshift.clusters
	cluster.encryption.enabled.value
	without_cmk(cluster)
	res := result.new(
		"Cluster does not use a customer managed encryption key.",
		cluster.encryption,
	)
}

is_not_encrypted(cluster) if value.is_false(cluster.encryption.enabled)

is_not_encrypted(cluster) if not cluster.encryption.enabled

without_cmk(cluster) if value.is_empty(cluster.encryption.kmskeyid)

without_cmk(cluster) if not cluster.encryption.kmskeyid
