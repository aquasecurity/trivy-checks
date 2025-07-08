# METADATA
# title: Send notification emails for high severity alerts
# description: |
#   It is recommended that at least one valid contact is configured for the security center.
#
#   Microsoft will notify the security contact directly in the event of a security incident using email and require alerting to be turned on.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://azure.microsoft.com/en-us/services/security-center/
# custom:
#   id: AZU-0044
#   aliases:
#     - AVD-AZU-0044
#     - alert-on-severe-notifications
#   long_id: azure-securitycenter-alert-on-severe-notifications
#   provider: azure
#   service: security-center
#   severity: MEDIUM
#   recommended_action: Set alert notifications to be on
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: securitycenter
#             provider: azure
#   examples: checks/cloud/azure/securitycenter/alert_on_severe_notifications.yaml
package builtin.azure.securitycenter.azure0044

import rego.v1

deny contains res if {
	some contact in input.azure.securitycenter.contacts
	isManaged(contact)

	not contact.enablealertnotifications.value
	res := result.new(
		"Security contact has alert notifications disabled.",
		object.get(contact, "enablealertnotifications", contact),
	)
}
