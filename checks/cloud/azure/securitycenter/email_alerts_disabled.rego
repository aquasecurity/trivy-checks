# METADATA
# title: Email Alerts Disabled
# description: |
#   If Defender for Cloud email alerts are disabled, high-severity issues may go unnoticed.
#
#   Email notifications should be enabled to ensure security contacts are notified of critical security alerts and incidents in a timely manner.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact
# custom:
#   id: AZU-0063
#   long_id: azure-securitycenter-email-alerts-disabled
#   aliases:
#     - AVD-AZU-0063
#     - email-alerts-disabled
#   provider: azure
#   service: security-center
#   severity: MEDIUM
#   recommended_action: Enable alert notifications in Defender for Cloud and configure security contacts.
#   minimum_trivy_version: 0.68.0
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: securitycenter
#             provider: azure
#   examples: checks/cloud/azure/securitycenter/email_alerts_disabled.yaml
package builtin.azure.securitycenter.azure0063

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some contact in input.azure.securitycenter.contacts
	isManaged(contact)

	alert_notifications_disabled(contact)
	res := result.new(
		"Security contact has email alert notifications disabled.",
		object.get(contact, "enablealertnotifications", contact),
	)
}

deny contains res if {
	some contact in input.azure.securitycenter.contacts
	isManaged(contact)

	alerts_to_admins_disabled(contact)
	res := result.new(
		"Security contact has email alerts to admins disabled.",
		object.get(contact, "enablealertstoadmins", contact),
	)
}

alert_notifications_disabled(contact) if {
	value.is_false(contact.enablealertnotifications)
}

alert_notifications_disabled(contact) if not contact.enablealertnotifications

alerts_to_admins_disabled(contact) if {
	value.is_false(contact.enablealertstoadmins)
}

alerts_to_admins_disabled(contact) if not contact.enablealertstoadmins
