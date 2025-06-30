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
#   examples: checks/cloud/digitalocean/compute/auto_upgrade_no_maintenance_policy.yaml
package builtin.digitalocean.compute.digitalocean0008

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.digitalocean.compute.kubernetesclusters
	isManaged(cluster)
	autoupgrade_disabled(cluster)
	res := result.new(
		"Kubernetes cluster does not have auto-upgrades enabled.",
		metadata.obj_by_path(cluster, ["autoupgrade"]),
	)
}

autoupgrade_disabled(cluster) if value.is_false(cluster.autoupgrade)

autoupgrade_disabled(cluster) if not cluster.autoupgrade
