# METADATA
# title: Launch configuration should not have a public IP address.
# description: |
#   You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html
# custom:
#   id: AWS-0009
#   aliases:
#     - AVD-AWS-0009
#     - no-public-ip
#   long_id: aws-ec2-no-public-ip
#   provider: aws
#   service: ec2
#   severity: HIGH
#   recommended_action: Set the instance to not be publicly accessible
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   examples: checks/cloud/aws/ec2/no_public_ip.yaml
package builtin.aws.ec2.aws0009

import rego.v1

deny contains res if {
	some cfg in input.aws.ec2.launchconfigurations
	cfg.associatepublicip.value == true
	res := result.new("Launch configuration associates public IP address.", cfg.associatepublicip)
}
