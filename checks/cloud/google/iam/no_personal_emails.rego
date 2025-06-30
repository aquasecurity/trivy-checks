# METADATA
# title: Not Proper Email Account In Use
# description: |
#   Service accounts and user accounts used in IAM bindings should follow organization email policies (e.g., no personal emails).
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam#google_project_iam_binding
# custom:
#   aliases:
#     - google-iam-not-proper-email-account-in-use
#   avd_id: AVD-GCP-0069
#   provider: google
#   service: iam
#   severity: LOW
#   short_code: not-proper-email-account
#   recommended_action: |
#     Use approved organizational email accounts for IAM bindings. Audit IAM policies to replace any personal or unapproved email accounts with proper service accounts or corporate emails.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   examples: checks/cloud/google/iam/no_personal_emails.yaml
package builtin.google.iam.google0069

import rego.v1

disallowed_domains := {
	"gmail.com",
	"yahoo.com",
	"hotmail.com",
	"outlook.com",
	"aol.com",
	"icloud.com",
	"protonmail.com",
	"mail.com",
	"zoho.com"
}

deny contains msg if {
	some binding in input.google.project_iam.bindings
	some member in binding.members
	is_disallowed_user_email(member)
	msg := sprintf("IAM member %q uses a public or personal email domain.", [member])
}

deny contains msg if {
	some entry in input.google.project_iam.members
	is_disallowed_user_email(entry.member)
	msg := sprintf("IAM member %q uses a public or personal email domain.", [entry.member])
}

is_disallowed_user_email(member) if {
	startswith(member, "user:")
	email := split(member, ":")[1]
	domain := split(email, "@")[1]
	disallowed_domains[domain]
}