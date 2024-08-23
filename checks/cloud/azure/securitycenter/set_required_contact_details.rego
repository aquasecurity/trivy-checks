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
#   id: AVD-AZU-0046
#   avd_id: AVD-AZU-0046
#   provider: azure
#   service: security-center
#   severity: LOW
#   short_code: set-required-contact-details
#   recommended_action: Set a telephone number for security center contact
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: securitycenter
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#phone
#     good_examples: checks/cloud/azure/securitycenter/set_required_contact_details.tf.go
#     bad_examples: checks/cloud/azure/securitycenter/set_required_contact_details.tf.go
package builtin.azure.securitycenter.azure0046

import rego.v1

deny contains res if {
	some contact in input.azure.securitycenter.contacts
	isManaged(contact)

	not contact_has_phone(contact)
	res := result.new(
		"Security contact does not have a phone number listed.",
		object.get(contact, "phone", contact),
	)
}

contact_has_phone(contact) := contact.phone.value != ""
