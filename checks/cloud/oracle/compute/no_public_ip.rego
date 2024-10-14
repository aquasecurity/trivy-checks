# METADATA
# title: Compute instance requests an IP reservation from a public pool
# description: |
#   Compute instance requests an IP reservation from a public pool
#
#   The compute instance has the ability to be reached from outside, you might want to sonder the use of a non public IP.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-OCI-0001
#   avd_id: AVD-OCI-0001
#   provider: oracle
#   service: compute
#   severity: CRITICAL
#   short_code: no-public-ip
#   recommended_action: Reconsider the use of an public IP
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: oracle
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_ip_address_reservation
#       - https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_instance
#     good_examples: checks/cloud/oracle/compute/no_public_ip.yaml
#     bad_examples: checks/cloud/oracle/compute/no_public_ip.yaml
package builtin.oracle.compute.oracle0001

import rego.v1

deny contains res if {
	some reservation in input.oracle.compute.addressreservations

	# TODO: future improvement: we need to see what this IP is used for before flagging
	reservation.pool.value == "public-ippool"

	res := result.new("Reservation made for public IP address.", reservation.pool)
}
