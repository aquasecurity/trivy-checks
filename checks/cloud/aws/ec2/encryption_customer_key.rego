# METADATA
# title: EBS volume encryption should use Customer Managed Keys
# description: |
#   Encryption using AWS keys provides protection for your EBS volume. To increase control of the encryption and manage factors like rotation use customer managed keys.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
# custom:
#   id: AVD-AWS-0027
#   avd_id: AVD-AWS-0027
#   provider: aws
#   service: ec2
#   severity: LOW
#   short_code: volume-encryption-customer-key
#   recommended_action: Enable encryption using customer managed keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#kms_key_id
#     good_examples: checks/cloud/aws/ec2/encryption_customer_key.tf.go
#     bad_examples: checks/cloud/aws/ec2/encryption_customer_key.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ec2/encryption_customer_key.cf.go
#     bad_examples: checks/cloud/aws/ec2/encryption_customer_key.cf.go
package builtin.aws.ec2.aws0027

import rego.v1

deny contains res if {
	some volume in input.aws.ec2.volumes
	volume.__defsec_metadata.managed
	volume.encryption.kmskeyid.value == ""
	res := result.new("EBS volume does not use a customer-managed KMS key.", volume.encryption.kmskeyid)
}
