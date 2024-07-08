# METADATA
# title: An ingress Network ACL rule allows specific ports from /0.
# description: |
#   Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
# custom:
#   id: AVD-AWS-0105
#   avd_id: AVD-AWS-0105
#   provider: aws
#   service: ec2
#   severity: CRITICAL
#   short_code: no-public-ingress-acl
#   recommended_action: Set a more restrictive cidr range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#cidr_block
#     good_examples: checks/cloud/aws/ec2/no_public_ingress_acl.tf.go
#     bad_examples: checks/cloud/aws/ec2/no_public_ingress_acl.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ec2/no_public_ingress_acl.cf.go
#     bad_examples: checks/cloud/aws/ec2/no_public_ingress_acl.cf.go
package builtin.aws.ec2.aws0105
