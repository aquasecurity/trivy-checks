# METADATA
# title: Stackdriver Logging should be enabled
# description: |
#   StackDriver logging provides a useful interface to all of stdout/stderr for each container and should be enabled for moitoring, debugging, etc.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0060
#   aliases:
#     - AVD-GCP-0060
#     - enable-stackdriver-logging
#   long_id: google-gke-enable-stackdriver-logging
#   provider: google
#   service: gke
#   severity: LOW
#   recommended_action: Enable StackDriver logging
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/enable_stackdriver_logging.yaml
package builtin.google.gke.google0060

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	cluster.loggingservice.value != "logging.googleapis.com/kubernetes"
	res := result.new(
		"Cluster does not use the logging.googleapis.com/kubernetes StackDriver logging service.",
		metadata.obj_by_path(cluster, ["loggingservice"]),
	)
}
