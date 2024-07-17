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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#monitoring_service
#     good_examples: checks/cloud/google/gke/enable_stackdriver_monitoring.tf.go
#     bad_examples: checks/cloud/google/gke/enable_stackdriver_monitoring.tf.go
package builtin.google.gke.google0052

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	cluster.monitoringservice.value != "monitoring.googleapis.com/kubernetes"
	res := result.new(
		"Cluster does not use the monitoring.googleapis.com/kubernetes StackDriver monitoring service.",
		cluster.monitoringservice,
	)
}
