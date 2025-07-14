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
#   id: GCP-0069
#   aliases:
#     - AVD-GCP-0069
#     - not-proper-email-account-in-use
#   long_id: google-iam-no-personal-emails
#   provider: google
#   service: iam
#   severity: LOW
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

import data.lib.google.iam

disallowed_domains := {
	"gmail.com",
	"yahoo.com",
	"hotmail.com",
	"outlook.com",
	"aol.com",
	"icloud.com",
	"protonmail.com",
	"mail.com",
	"zoho.com",
}

deny contains res if {
	some binding in iam.all_bindings
	some member in binding.members
	is_disallowed_user_email(member.value)
	res := result.new(
		sprintf("IAM member %q uses a public or personal email domain.", [member.value]),
		member,
	)
}

deny contains res if {
	some entry in iam.all_members
	is_disallowed_user_email(entry.member.value)
	res := result.new(
		sprintf("IAM member %q uses a public or personal email domain.", [entry.member.value]),
		entry.member,
	)
}

is_disallowed_user_email(member) if {
	startswith(member, "user:")
	email := split(member, ":")[1]
	domain := split(email, "@")[1]
	disallowed_domains[domain]
}
