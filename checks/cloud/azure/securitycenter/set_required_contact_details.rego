# METADATA
# title: The required contact details should be set for security center
# description: |
#   It is recommended that at least one valid contact is configured for the security center.
#
#   Microsoft will notify the security contact directly in the event of a security incident and will look to use a telephone number in cases where a prompt response is required.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://azure.microsoft.com/en-us/services/security-center/
# custom:
#   id: AZU-0046
#   aliases:
#     - AVD-AZU-0046
#     - set-required-contact-details
#   long_id: azure-securitycenter-set-required-contact-details
#   provider: azure
#   service: security-center
#   severity: LOW
#   recommended_action: Set a telephone number for security center contact
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: securitycenter
#             provider: azure
#   examples: checks/cloud/azure/securitycenter/set_required_contact_details.yaml
package builtin.azure.securitycenter.azure0046

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some contact in input.azure.securitycenter.contacts
	isManaged(contact)
	contact_without_phone(contact)
	res := result.new(
		"Security contact does not have a phone number listed.",
		object.get(contact, "phone", contact),
	)
}

contact_without_phone(contact) if value.is_empty(contact.phone)

contact_without_phone(contact) if not contact.phone
