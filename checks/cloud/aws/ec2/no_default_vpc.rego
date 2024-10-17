# METADATA
# title: AWS best practice to not use the default VPC for workflows
# description: |
#   Default VPC does not have a lot of the critical security features that standard VPC comes with, new resources should not be created in the default VPC and it should not be present in the Terraform.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html
# custom:
#   id: AVD-AWS-0101
#   avd_id: AVD-AWS-0101
#   aliases:
#     - aws-vpc-no-default-vpc
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: no-default-vpc
#   recommended_action: Create a non-default vpc for resources to be created in
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc
#     good_examples: checks/cloud/aws/ec2/no_default_vpc.yaml
#     bad_examples: checks/cloud/aws/ec2/no_default_vpc.yaml
package builtin.aws.ec2.aws0101

import rego.v1

deny contains res if {
	some vpc in input.aws.ec2.vpcs
	vpc.isdefault.value == true
	res := result.new("Default VPC is used.", vpc)
}
