# METADATA
# title: A security group rule allows egress traffic to multiple public addresses
# description: |
#   Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-OPNSTK-0004
#   avd_id: AVD-OPNSTK-0004
#   provider: openstack
#   service: networking
#   severity: MEDIUM
#   short_code: no-public-egress
#   recommended_action: Employ more restrictive security group rules
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: networking
#             provider: openstack
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/networking_secgroup_rule_v2
#     good_examples: checks/cloud/openstack/networking/no_public_egress.yaml
#     bad_examples: checks/cloud/openstack/networking/no_public_egress.yaml
package builtin.openstack.networking.openstack0004

import rego.v1

deny contains res if {
	some sg in input.openstack.networking.securitygroups
	some rule in sg.rules
	not is_ingress(rule)
	cidr.is_public(rule.cidr.value)
	cidr.count_addresses(rule.cidr.value) > 1
	res := result.new("Security group rule allows egress to multiple public addresses.", rule.cidr)
}

is_ingress(rule) := rule.isingress.value == true
