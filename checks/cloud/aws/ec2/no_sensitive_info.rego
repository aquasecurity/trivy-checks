# METADATA
# title: Ensure all data stored in the launch configuration EBS is securely encrypted
# description: |
#   When creating Launch Configurations, user data can be used for the initial configuration of the instance. User data must not contain any sensitive data.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AWS-0122
#   aliases:
#     - AVD-AWS-0122
#     - aws-autoscaling-no-sensitive-info
#     - no-sensitive-info
#   long_id: aws-ec2-no-sensitive-info
#   provider: aws
#   service: ec2
#   severity: HIGH
#   recommended_action: Don't use sensitive data in user data
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   examples: checks/cloud/aws/ec2/no_sensitive_info.yaml
package builtin.aws.ec2.aws0122

import rego.v1

deny contains res if {
	some conf in input.aws.ec2.launchconfigurations
	scan_result := squealer.scan_string(conf.userdata.value)
	scan_result.transgressionFound
	res := result.new(
		sprintf("Sensitive data found in user data: %s", [scan_result.description]),
		conf.userdata,
	)
}
