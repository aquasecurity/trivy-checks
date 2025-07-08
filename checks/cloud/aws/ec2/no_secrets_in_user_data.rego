# METADATA
# title: User data for EC2 instances must not contain sensitive AWS keys
# description: |
#   EC2 instance data is used to pass start up information into the EC2 instance. This userdata must not contain access key credentials. Instead use an IAM Instance Profile assigned to the instance to grant access to other AWS Services.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html
# custom:
#   id: AWS-0029
#   aliases:
#     - AVD-AWS-0029
#     - aws-autoscaling-no-public-ip
#     - no-secrets-in-user-data
#   long_id: aws-ec2-no-secrets-in-user-data
#   provider: aws
#   service: ec2
#   severity: CRITICAL
#   recommended_action: Remove sensitive data from the EC2 instance user-data
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   examples: checks/cloud/aws/ec2/no_secrets_in_user_data.yaml
package builtin.aws.ec2.aws0029

import rego.v1

deny contains res if {
	some instance in input.aws.ec2.instances
	isManaged(instance)
	scan_result := squealer.scan_string(instance.userdata.value)
	scan_result.transgressionFound
	res := result.new(
		sprintf("Sensitive data found in instance user data: %s", [scan_result.description]),
		instance.userdata,
	)
}
