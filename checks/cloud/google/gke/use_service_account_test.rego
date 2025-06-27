package builtin.google.gke.google0050

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	default_account_is_not_overrided(cluster)
	res := result.new(
		"Cluster does not override the default service account.",
		metadata.obj_by_path(cluster, ["nodeconfig", "serviceaccount"]),
	)
}

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	not cluster.enableautpilot.value # Node pools cannot be directly managed in GKE Autopilot
	some pool in cluster.nodepools
	pool_default_account_is_not_overrided(pool.nodeconfig)
	res := result.new(
		"Node pool does not override the default service account.",
		metadata.obj_by_path(pool, ["nodeconfig", "serviceaccount"]),
	)
}

pool_default_account_is_not_overrided(nodeconfig) if value.is_empty(nodeconfig.serviceaccount)

pool_default_account_is_not_overrided(nodeconfig) if not nodeconfig.serviceaccount

default_account_is_not_overrided(cluster) if {
	not autoscaling_or_autopilot_enabled(cluster)
	not cluster.removedefaultnodepool.value
	value.is_empty(cluster.nodeconfig.serviceaccount)
}

default_account_is_not_overrided(cluster) if {
	not autoscaling_or_autopilot_enabled(cluster)
	not cluster.removedefaultnodepool.value
	not cluster.nodeconfig.serviceaccount
}

default_account_is_not_overrided(cluster) if {
	autoscaling_or_autopilot_enabled(cluster)
	value.is_empty(cluster.autoscaling.autoprovisioningdefaults.serviceaccount)
}

default_account_is_not_overrided(cluster) if {
	autoscaling_or_autopilot_enabled(cluster)
	not cluster.autoscaling.autoprovisioningdefaults.serviceaccount
}

autoscaling_or_autopilot_enabled(cluster) if cluster.autoscaling.enabled.value

autoscaling_or_autopilot_enabled(cluster) if cluster.enableautpilot.value
