# METADATA
# title: DAX Cluster should always encrypt data at rest
# description: |
#   Data can be freely read if compromised. Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection by helping secure your data from unauthorized access to the underlying storage.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html
#   - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html
# custom:
#   id: AVD-AWS-0023
#   avd_id: AVD-AWS-0023
#   provider: aws
#   service: dynamodb
#   severity: HIGH
#   short_code: enable-at-rest-encryption
#   recommended_action: Enable encryption at rest for DAX Cluster
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: dynamodb
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster#server_side_encryption
#     good_examples: checks/cloud/aws/dynamodb/enable_at_rest_encryption.tf.go
#     bad_examples: checks/cloud/aws/dynamodb/enable_at_rest_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/dynamodb/enable_at_rest_encryption.cf.go
#     bad_examples: checks/cloud/aws/dynamodb/enable_at_rest_encryption.cf.go
package builtin.aws.dynamodb.aws0023

import rego.v1

deny contains res if {
	some cluster in input.aws.dynamodb.daxclusters
	cluster.serversideencryption.enabled.value == false
	res := result.new("DAX encryption is not enabled.", cluster.serversideencryption.enabled)
}
