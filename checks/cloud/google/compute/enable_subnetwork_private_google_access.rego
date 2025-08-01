# METADATA
# title: Google Compute Subnetwork with Private Google Access Disabled
# description: |
#   Private Google Access allows instances in a subnet to reach Google APIs and services via internal IP, which should be enabled for private networks.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_subnetwork#private_ip_google_access
#   - https://cloud.google.com/architecture/best-practices-vpc-design#limit-access
# custom:
#   id: GCP-0075
#   aliases:
#     - google-misc-google-compute-subnetwork-with-private-google-access-disable
#     - AVD-GCP-0075
#   long_id: google-compute-enable-subnetwork-private-google-access
#   provider: google
#   service: compute
#   severity: LOW
#   minimum_trivy_version: 0.65.0
#   recommended_action: |
#     Enable Private Google Access on subnets. In Terraform, set `private_ip_google_access = true` in the `google_compute_subnetwork` resource.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/enable_subnetwork_private_google_access.yaml
package builtin.google.compute.google0075

import rego.v1

deny contains res if {
	some subnetwork in input.google.compute.networks[_].subnetworks
	subnetwork.privateipgoogleaccess.value == false
	subnetwork.privateipgoogleaccess.explicit
	res := result.new(
		"Subnetwork has Private Google Access explicitly disabled.",
		subnetwork.privateipgoogleaccess,
	)
}

deny contains res if {
	some subnetwork in input.google.compute.networks[_].subnetworks
	subnetwork.privateipgoogleaccess.value == false
	not subnetwork.privateipgoogleaccess.explicit
	res := result.new(
		"Subnetwork does not have Private Google Access configured.",
		subnetwork.privateipgoogleaccess,
	)
}
