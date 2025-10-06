# METADATA
# title: Avoid using 'latest' tag in container images
# description: |
#   The 'latest' tag in container images does not guarantee consistency across deployments.
#   Using explicit version tags ensures that the exact image version is used,
#   reducing the risk of unexpected changes or vulnerabilities in your environment.
#
#   Avoid using 'latest' in your `docker-compose.yaml` files to maintain predictable deployments.
# scope: package
# related_resources:
#   - https://docs.docker.com/reference/compose-file/services/#image
# custom:
#   id: USR-COMPOSE-0001
#   avd_id: USR-COMPOSE-0001
#   provider: generic
#   severity: MEDIUM
#   short_code: avoid-latest-tag
#   recommended_action: Use specific image tags instead of 'latest' for reliable deployments.
#   input:
#     selector:
#       - type: yaml
package user.compose.latest_tag

import rego.v1

deny contains res if {
	some name, service in input.services
	endswith(service.image, ":latest")
	res := result.new(sprintf("Avoid using 'latest' tag in container image for %q", [name]), {})
}
