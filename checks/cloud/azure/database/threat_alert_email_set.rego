# METADATA
# title: At least one email address is set for threat alerts
# description: |
#   SQL Server sends alerts for threat detection via email, if there are no email addresses set then mitigation will be delayed.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0018
#   avd_id: AVD-AZU-0018
#   provider: azure
#   service: database
#   severity: MEDIUM
#   short_code: threat-alert-email-set
#   recommended_action: Provide at least one email address for threat alerts
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#email_addresses
#     good_examples: checks/cloud/azure/database/threat_alert_email_set.yaml
#     bad_examples: checks/cloud/azure/database/threat_alert_email_set.yaml
package builtin.azure.database.azure0018

import rego.v1

deny contains res if {
	some server in input.azure.database.mssqlservers
	some policy in server.securityalertpolicies
	not has_emails(policy)
	res := result.new(
		"Security alert policy does not include any email addresses for notification.",
		policy,
	)
}

has_emails(policy) := count(policy.emailaddresses) > 0
