# METADATA
# title: Ensure a log metric filter and alarm exist for organisation changes
# description: |
#   Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or
#   intentional modifications that may lead to unauthorized access or other security breaches.
#   This monitoring technique helps you to ensure that any unexpected changes performed
#   within your AWS Organizations can be investigated and any unwanted changes can be
#   rolled back.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_security_incident-response.html
# custom:
#   id: AVD-AWS-0174
#   avd_id: AVD-AWS-0174
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-org-changes-alarm
#   recommended_action: Create an alarm to alert on organisation changes
#   frameworks:
#     cis-aws-1.4:
#       - "4.15"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0174

import rego.v1

import data.lib.aws.trails

deny contains res if {
	some trail in trails.trails_without_filter([
		"$.eventSource = organizations.amazonaws.com",
		`$.eventSource = "organizations.amazonaws.com"`,
	])
	res := result.new("Cloudwatch has no organisation changes log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter([
		"$.eventSource = organizations.amazonaws.com",
		`$.eventSource = "organizations.amazonaws.com"`,
	])
	res := result.new("Cloudwatch has organisation changes alarm", trail)
}
