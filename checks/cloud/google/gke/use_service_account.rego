# METADATA
# title: Checks for service account defined for GKE nodes
# description: |
#   You should create and use a minimally privileged service account to run your GKE cluster instead of using the Compute Engine default service account.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa
# custom:
#   id: AVD-GCP-0050
#   avd_id: AVD-GCP-0050
#   provider: google
#   service: gke
#   severity: MEDIUM
#   short_code: use-service-account
#   recommended_action: Use limited permissions for service accounts to be effective
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#service_account
#     good_examples: checks/cloud/google/gke/use_service_account.tf.go
#     bad_examples: checks/cloud/google/gke/use_service_account.tf.go
package builtin.google.gke.google0050

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	cluster.removedefaultnodepool.value == false
	cluster.nodeconfig.serviceaccount.value == ""
	res := result.new(
		"Cluster does not override the default service account.",
		cluster.nodeconfig.serviceaccount,
	)
}

deny contains res if {
	some cluster in input.google.gke.clusters
	some pool in cluster.nodepools
	pool.nodeconfig.serviceaccount.value == ""
	res := result.new(
		"Node pool does not override the default service account.",
		pool.nodeconfig.serviceaccount,
	)
}
