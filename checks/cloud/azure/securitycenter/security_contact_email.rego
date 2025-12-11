# METADATA
# title: Security Contact Email
# description: |
#   Without a configured security contact email, critical alerts from Microsoft Defender for Cloud may go unnoticed, delaying incident response.
#
#   Microsoft will notify the security contact directly in the event of a security incident and will look to use email for notifications.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#email
# custom:
#   id: AZU-0062
#   long_id: azure-securitycenter-security-contact-email
#   aliases:
#     - AVD-AZU-0062
#     - security-contact-email
#   provider: azure
#   service: security-center
#   severity: MEDIUM
#   recommended_action: Set additional security contact emails in Defender for Cloud under Environment Settings > Email notifications.
#   minimum_trivy_version: 0.68.0
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: securitycenter
#             provider: azure
#   examples: checks/cloud/azure/securitycenter/security_contact_email.yaml
package builtin.azure.securitycenter.azure0062

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some contact in input.azure.securitycenter.contacts
	isManaged(contact)
	contact_without_email(contact)
	res := result.new(
		"Security contact does not have an email address configured.",
		object.get(contact, "email", contact),
	)
}

contact_without_email(contact) if {
	value.is_empty(contact.email)
}

contact_without_email(contact) if not contact.email
