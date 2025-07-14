# METADATA
# title: GitHub branch protection does not require signed commits.
# description: |
#   GitHub branch protection should be set to require signed commits.
#
#   You can do this by setting the <code>require_signed_commits</code> attribute to 'true'.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection#require_signed_commits
#   - https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification
#   - https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches#require-signed-commits
# custom:
#   id: GIT-0004
#   aliases:
#     - AVD-GIT-0004
#     - require_signed_commits
#   long_id: github-branchprotections-require-signed-commits
#   provider: github
#   service: branchprotections
#   severity: HIGH
#   recommended_action: Require signed commits
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: branchprotections
#             provider: github
#   examples: checks/cloud/github/branch_protections/require_signed_commits.yaml
package builtin.github.branch_protections.github0004

import rego.v1

deny contains res if {
	some protection in input.github.branchprotections
	protection.requiresignedcommits.value == false
	res := result.new("Branch protection does not require signed commits.", protection.requiresignedcommits)
}
