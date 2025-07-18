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
#   aliases:
#     - google-misc-google-compute-subnetwork-logging-disabled
#     - AVD-GCP-0076
#   long_id: google-compute-enable-subnetwork-flow-logs
#   provider: google
#   service: compute
#   severity: MEDIUM
#   short_code: google-compute-subnetwork-logging
#   recommended_action: |
#     Enable VPC Flow Logs for subnets. In Terraform, set `enable_flow_logs = true` in the `google_compute_subnetwork` resource.
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
	is_flow_logs_disabled(subnetwork)
	res := result.new(
		"Subnetwork does not have flow logs enabled.",
		object.get(subnetwork, "enableflowlogs", subnetwork),
	)
}

deny contains res if {
	some subnetwork in input.google.compute.networks[_].subnetworks
	is_flow_logs_configured(subnetwork)
	res := result.new(
		"Subnetwork does not have flow logs configured.",
		object.get(subnetwork, "enableflowlogs", subnetwork),
	)
}

is_flow_logs_disabled(subnetwork) if {
	subnetwork.enableflowlogs.value == false
}

is_flow_logs_configured(subnetwork) if {
	not "enableflowlogs" in object.keys(subnetwork)
}
