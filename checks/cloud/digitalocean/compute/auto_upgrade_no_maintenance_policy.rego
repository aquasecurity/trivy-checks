# METADATA
# title: Kubernetes clusters should be auto-upgraded to ensure that they always contain the latest security patches.
# description: |
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.digitalocean.com/products/kubernetes/resources/best-practices/
# custom:
#   id: AVD-DIG-0008
#   avd_id: AVD-DIG-0008
#   provider: digitalocean
#   service: compute
#   severity: CRITICAL
#   short_code: kubernetes-auto-upgrades-not-enabled
#   recommended_action: Set maintenance policy deterministically when auto upgrades are enabled
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: digitalocean
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_cluster#auto-upgrade-example
#     good_examples: checks/cloud/digitalocean/compute/auto_upgrade_no_maintenance_policy.tf.go
#     bad_examples: checks/cloud/digitalocean/compute/auto_upgrade_no_maintenance_policy.tf.go
package builtin.digitalocean.compute.digitalocean0008

import rego.v1

deny contains res if {
	some cluster in input.digitalocean.compute.kubernetesclusters
	isManaged(cluster)
	not cluster.autoupgrade.value
	res := result.new(
		"Kubernetes cluster does not have auto-upgrades enabled.",
		object.get(cluster, "autoupgrade", cluster),
	)
}
