# METADATA
# title: An ingress nas security group rule allows traffic from /0.
# description: |
#   Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/api/nas/AuthorizeNASSecurityGroupIngress.htm
# custom:
#   id: AVD-NIF-0014
#   avd_id: AVD-NIF-0014
#   provider: nifcloud
#   service: nas
#   severity: CRITICAL
#   short_code: no-public-ingress-nas-sgr
#   recommended_action: Set a more restrictive cidr range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: nas
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_security_group#cidr_ip
#     good_examples: checks/cloud/nifcloud/nas/no_public_ingress_nas_sgr.tf.go
#     bad_examples: checks/cloud/nifcloud/nas/no_public_ingress_nas_sgr.tf.go
package builtin.nifcloud.nas.nifcloud0014

import rego.v1

deny contains res if {
	some sg in input.nifcloud.nas.nassecuritygroups
	some c in sg.cidrs
	cidr.is_public(c.value)
	cidr.count_addresses(c.value) > 1
	res := result.new("Security group rule allows ingress from public internet.", c)
}
