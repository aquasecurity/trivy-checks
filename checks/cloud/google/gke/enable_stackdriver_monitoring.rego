# METADATA
# title: Stackdriver Monitoring should be enabled
# description: |
#   StackDriver monitoring aggregates logs, events, and metrics from your Kubernetes environment on GKE to help you understand your application's behavior in production.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0052
#   avd_id: AVD-GCP-0052
#   provider: google
#   service: gke
#   severity: LOW
#   short_code: enable-stackdriver-monitoring
#   recommended_action: Enable StackDriver monitoring
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/enable_stackdriver_monitoring.yaml
package builtin.google.gke.google0052

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	not use_kub_service(cluster)
	res := result.new(
		"Cluster does not use the monitoring.googleapis.com/kubernetes StackDriver monitoring service.",
		metadata.obj_by_path(cluster, ["monitoringservice"]),
	)
}

use_kub_service(cluster) if cluster.monitoringservice.value == "monitoring.googleapis.com/kubernetes"
