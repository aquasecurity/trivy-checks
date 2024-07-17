# METADATA
# title: Stackdriver Logging should be enabled
# description: |
#   StackDriver logging provides a useful interface to all of stdout/stderr for each container and should be enabled for moitoring, debugging, etc.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0060
#   avd_id: AVD-GCP-0060
#   provider: google
#   service: gke
#   severity: LOW
#   short_code: enable-stackdriver-logging
#   recommended_action: Enable StackDriver logging
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#logging_service
#     good_examples: checks/cloud/google/gke/enable_stackdriver_logging.tf.go
#     bad_examples: checks/cloud/google/gke/enable_stackdriver_logging.tf.go
package builtin.google.gke.google0060

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	cluster.loggingservice.value != "logging.googleapis.com/kubernetes"
	res := result.new("Cluster does not use the logging.googleapis.com/kubernetes StackDriver logging service.", cluster.loggingservice)
}
