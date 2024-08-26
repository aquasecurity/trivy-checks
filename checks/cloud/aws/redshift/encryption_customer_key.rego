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
#     good_examples: checks/cloud/aws/redshift/encryption_customer_key.tf.go
#     bad_examples: checks/cloud/aws/redshift/encryption_customer_key.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/redshift/encryption_customer_key.cf.go
#     bad_examples: checks/cloud/aws/redshift/encryption_customer_key.cf.go
package builtin.aws.redshift.aws0084

import rego.v1

deny contains res if {
	some cluster in input.aws.redshift.clusters
	not is_encrypted(cluster)
	res := result.new(
		"Cluster does not have encryption enabled.",
		cluster.encryption,
	)
}

deny contains res if {
	some cluster in input.aws.redshift.clusters
	is_encrypted(cluster)
	not has_kms_key(cluster)
	res := result.new(
		"Cluster does not use a customer managed encryption key.",
		cluster.encryption,
	)
}

is_encrypted(cluster) if cluster.encryption.enabled.value

has_kms_key(cluster) if cluster.encryption.kmskeyid.value != ""
