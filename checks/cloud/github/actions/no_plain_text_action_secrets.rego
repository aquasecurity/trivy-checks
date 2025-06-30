# METADATA
# title: Ensure plaintext value is not used for GitHub Action Environment Secret.
# description: |
#   For the purposes of security, the contents of the plaintext_value field have been marked as sensitive to Terraform, but this does not hide it from state files. State should be treated as sensitive always.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_environment_secret
#   - https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
# custom:
#   id: AVD-GIT-0002
#   avd_id: AVD-GIT-0002
#   provider: github
#   service: environmentsecrets
#   severity: HIGH
#   short_code: no-plain-text-action-secrets
#   recommended_action: Do not store plaintext values in your code but rather populate the encrypted_value using fields from a resource, data source or variable.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: environmentsecrets
#             provider: github
#   examples: checks/cloud/github/actions/no_plain_text_action_secrets.yaml
package builtin.github.actions.github0002

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some secret in input.github.environmentsecrets
	value.is_not_empty(secret.plaintextvalue)
	res := result.new("Secret has plain text value", secret.plaintextvalue)
}
