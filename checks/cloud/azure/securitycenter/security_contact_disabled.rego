# METADATA
# title: Security Contact Disabled
# description: |
#   If a security contact is disabled, critical alerts from Microsoft Defender for Cloud will not be delivered to that contact, potentially causing security incidents to go unnoticed.
#
#   Security contacts should be enabled to ensure that designated personnel receive timely notifications about security threats and incidents.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact
# custom:
#   id: AZU-0064
#   long_id: azure-securitycenter-security-contact-disabled
#   aliases:
#     - AVD-AZU-0064
#     - security-contact-disabled
#   provider: azure
#   service: security-center
#   severity: HIGH
#   recommended_action: Enable the security contact to ensure security notifications are delivered.
#   minimum_trivy_version: 0.68.0
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: securitycenter
#             provider: azure
#   examples: checks/cloud/azure/securitycenter/security_contact_disabled.yaml
package builtin.azure.securitycenter.azure0064

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some contact in input.azure.securitycenter.contacts
	isManaged(contact)

	contact_disabled(contact)
	res := result.new(
		"Security contact is disabled and will not receive notifications.",
		object.get(contact, "isenabled", contact),
	)
}

contact_disabled(contact) if {
	isManaged(contact.isenabled)
	value.is_false(contact.isenabled)
}
