# METADATA
# title: Instances in a subnet should not receive a public IP address by default.
# description: |
#   You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html#concepts-public-addresses
# custom:
#   id: AVD-AWS-0164
#   avd_id: AVD-AWS-0164
#   aliases:
#     - aws-vpc-no-public-ingress-sgr
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: no-public-ip-subnet
#   recommended_action: Set the instance to not be publicly accessible
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet#map_public_ip_on_launch
#     good_examples: checks/cloud/aws/ec2/no_public_ip_subnet.yaml
#     bad_examples: checks/cloud/aws/ec2/no_public_ip_subnet.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/ec2/no_public_ip_subnet.yaml
#     bad_examples: checks/cloud/aws/ec2/no_public_ip_subnet.yaml
package builtin.aws.ec2.aws0164

import rego.v1

deny contains res if {
	some subnet in input.aws.ec2.subnets
	subnet.mappubliciponlaunch.value == true
	res := result.new("Subnet associates public IP address.", subnet.mappubliciponlaunch)
}
