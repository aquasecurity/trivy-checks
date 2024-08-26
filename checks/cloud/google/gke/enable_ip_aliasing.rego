# METADATA
# title: Clusters should have IP aliasing enabled
# description: |
#   IP aliasing allows the reuse of public IPs internally, removing the need for a NAT gateway.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0049
#   avd_id: AVD-GCP-0049
#   provider: google
#   service: gke
#   severity: LOW
#   short_code: enable-ip-aliasing
#   recommended_action: Enable IP aliasing
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#ip_allocation_policy
#     good_examples: checks/cloud/google/gke/enable_ip_aliasing.tf.go
#     bad_examples: checks/cloud/google/gke/enable_ip_aliasing.tf.go
package builtin.google.gke.google0049

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	cluster.ipallocationpolicy.enabled.value == false
	res := result.new("Cluster has IP aliasing disabled.", cluster.ipallocationpolicy.enabled)
}
