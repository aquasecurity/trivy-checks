# METADATA
# title: AWS Classic resource usage.
# description: |
#   AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
#   resources in a VPC instead.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html
# custom:
#   id: AWS-0085
#   aliases:
#     - AVD-AWS-0085
#     - no-classic-resources
#   long_id: aws-redshift-no-classic-resources
#   provider: aws
#   service: redshift
#   severity: CRITICAL
#   recommended_action: Switch to VPC resources
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: redshift
#             provider: aws
#   examples: checks/cloud/aws/redshift/no_classic_resources.yaml
package builtin.aws.redshift.aws0085

import rego.v1

deny contains res if {
	some group in input.aws.redshift.securitygroups
	res := result.new(
		"Classic resources should not be used.",
		group,
	)
}
