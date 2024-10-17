# METADATA
# title: Security threat alerts go to subcription owners and co-administrators
# description: |
#   Subscription owners should be notified when there are security alerts. By ensuring the administrators of the account have been notified they can quickly assist in any required remediation
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0023
#   avd_id: AVD-AZU-0023
#   provider: azure
#   service: database
#   severity: LOW
#   short_code: threat-alert-email-to-owner
#   recommended_action: Enable email to subscription owners
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#email_account_admins
#     good_examples: checks/cloud/azure/database/threat_alert_email_to_owner.yaml
#     bad_examples: checks/cloud/azure/database/threat_alert_email_to_owner.yaml
package builtin.azure.database.azure0023

import rego.v1

deny contains res if {
	some server in input.azure.database.mssqlservers
	some policy in server.securityalertpolicies
	not policy.emailaccountadmins.value
	res := result.new(
		"Security alert policy does not alert account admins.",
		object.get(policy, "emailaccountadmins", policy),
	)
}
