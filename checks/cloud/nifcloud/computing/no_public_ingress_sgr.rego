# METADATA
# title: An ingress security group rule allows traffic from /0.
# description: |
#   Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
#
#   When publishing web applications, use a load balancer instead of publishing directly to instances.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/help/fw/rule_new.htm
# custom:
#   id: AVD-NIF-0001
#   avd_id: AVD-NIF-0001
#   provider: nifcloud
#   service: computing
#   severity: CRITICAL
#   short_code: no-public-ingress-sgr
#   recommended_action: Set a more restrictive cidr range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: computing
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#cidr_ip
#     good_examples: checks/cloud/nifcloud/computing/no_public_ingress_sgr.tf.go
#     bad_examples: checks/cloud/nifcloud/computing/no_public_ingress_sgr.tf.go
package builtin.nifcloud.computing.nifcloud0001

import rego.v1

deny contains res if {
	some sg in input.nifcloud.computing.securitygroups
	some rule in sg.ingressrules
	cidr.is_public(rule.cidr.value)
	cidr.count_addresses(rule.cidr.value) > 0
	res := result.new("Security group rule allows ingress from public internet.", rule.cidr)
}
