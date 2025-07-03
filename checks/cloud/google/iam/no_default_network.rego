# METADATA
# title: Default network should not be created at project level
# description: |
#   The default network which is provided for a project contains multiple insecure firewall rules which allow ingress to the project's infrastructure. Creation of this network should therefore be disabled.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   aliases:
#     - google-iam-no-default-network
#   id: GCP-0010
#   provider: google
#   service: iam
#   severity: HIGH
#   long_id: google-iam-no-default-network
#   recommended_action: Disable automatic default network creation
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   examples: checks/cloud/google/iam/no_default_network.yaml
package builtin.google.iam.google0010

import rego.v1

# TODO: check constraints before auto_create_network
deny contains res if {
	some project in input.google.iam.projects
	isManaged(project)
	project.autocreatenetwork.value == true
	res := result.new("Project has automatic network creation enabled.", project.autocreatenetwork)
}
