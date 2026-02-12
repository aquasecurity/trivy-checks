# METADATA
# title: Google Compute Subnetwork Logging Disabled
# description: |
#   Flow logs for subnets should be enabled to capture network traffic details for security analysis.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_subnetwork
#   - https://cloud.google.com/architecture/best-practices-vpc-design#tailor-logging
# custom:
#   id: GCP-0076
#   long_id: google-compute-google-compute-subnetwork-logging
#   aliases:
#     - AVD-GCP-0076
#     - google-compute-subnetwork-logging
#     - google-compute-google-compute-subnetwork-logging
#     - google-misc-google-compute-subnetwork-logging-disabled
#   provider: google
#   service: compute
#   severity: MEDIUM
#   recommended_action: Enable VPC Flow Logs for subnets.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/enable_subnetwork_flow_logs.yaml
package builtin.google.compute.google0076

import rego.v1

deny contains res if {
	some subnetwork in input.google.compute.networks[_].subnetworks
	not is_proxy_only_network(subnetwork)
	is_flow_logs_disabled(subnetwork)
	res := result.new(
		"Subnetwork does not have flow logs enabled.",
		object.get(subnetwork, "enableflowlogs", subnetwork),
	)
}

deny contains res if {
	some subnetwork in input.google.compute.networks[_].subnetworks
	not is_proxy_only_network(subnetwork)
	not flow_logs_configured(subnetwork)
	res := result.new(
		"Subnetwork does not have flow logs configured.",
		subnetwork,
	)
}

is_proxy_only_network(subnetwork) if subnetwork.purpose.value in {"REGIONAL_MANAGED_PROXY", "GLOBAL_MANAGED_PROXY"}

is_flow_logs_disabled(subnetwork) if subnetwork.enableflowlogs.value == false

flow_logs_configured(subnetwork) if {
	"enableflowlogs" in object.keys(subnetwork)
}
