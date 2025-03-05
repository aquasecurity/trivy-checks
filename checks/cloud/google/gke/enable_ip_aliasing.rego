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
#   examples: checks/cloud/google/gke/enable_ip_aliasing.yaml
package builtin.google.gke.google0049

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	not cluster.ipallocationpolicy.enabled.value
	res := result.new(
		"Cluster has IP aliasing disabled.",
		metadata.obj_by_path(cluster, ["ipallocationpolicy", "enabled"]),
	)
}
