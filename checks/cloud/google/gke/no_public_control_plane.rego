# METADATA
# title: GKE Control Plane should not be publicly accessible
# description: |
#   The GKE control plane is exposed to the public internet by default.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0053
#   avd_id: AVD-GCP-0053
#   provider: google
#   service: gke
#   severity: HIGH
#   short_code: no-public-control-plane
#   recommended_action: Use private nodes and master authorised networks to prevent exposure
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/no_public_control_plane.yaml
package builtin.google.gke.google0053

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	some block in cluster.masterauthorizednetworks.cidrs
	cidr.is_public(block.value)
	res := result.new("Cluster exposes control plane to the public internet.", block)
}
