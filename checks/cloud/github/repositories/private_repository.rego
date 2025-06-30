# METADATA
# title: GitHub repository shouldn't be public.
# description: |
#   GitHub repository should be set to be private.
#
#   You can do this by either setting <code>private</code> attribute to 'true' or <code>visibility</code> attribute to 'internal' or 'private'.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-repository-visibility
#   - https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-repository-visibility#about-internal-repositories
# custom:
#   id: AVD-GIT-0001
#   avd_id: AVD-GIT-0001
#   provider: github
#   service: repositories
#   severity: CRITICAL
#   short_code: private
#   recommended_action: Make sensitive or commercially important repositories private
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: repositories
#             provider: github
#   examples: checks/cloud/github/repositories/private_repository.yaml
package builtin.github.repositories.github0001

import rego.v1

deny contains res if {
	some repo in input.github.repositories
	repo.public.value == true
	res := result.new("Repository is public.", repo.public)
}
