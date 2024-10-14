# METADATA
# title: Legacy ABAC permissions are enabled.
# description: |
#   You should disable Attribute-Based Access Control (ABAC), and instead use Role-Based Access Control (RBAC) in GKE.
#
#   RBAC has significant security advantages and is now stable in Kubernetes, so it’s time to disable ABAC.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled_default_for_110
# custom:
#   id: AVD-GCP-0062
#   avd_id: AVD-GCP-0062
#   provider: google
#   service: gke
#   severity: HIGH
#   short_code: use-rbac-permissions
#   recommended_action: Switch to using RBAC permissions
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_legacy_abac
#     good_examples: checks/cloud/google/gke/use_rbac_permissions.yaml
#     bad_examples: checks/cloud/google/gke/use_rbac_permissions.yaml
package builtin.google.gke.google0062

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	cluster.enablelegacyabac.value == true
	res := result.new("Cluster has legacy ABAC enabled.", cluster.enablelegacyabac)
}
