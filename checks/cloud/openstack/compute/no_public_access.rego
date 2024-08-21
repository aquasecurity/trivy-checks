# METADATA
# title: A firewall rule allows traffic from/to the public internet
# description: |
#   Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-OPNSTK-0002
#   avd_id: AVD-OPNSTK-0002
#   provider: openstack
#   service: compute
#   severity: MEDIUM
#   short_code: no-public-access
#   recommended_action: Employ more restrictive firewall rules
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: openstack
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/fw_rule_v1
#     good_examples: checks/cloud/openstack/compute/no_public_access.tf.go
#     bad_examples: checks/cloud/openstack/compute/no_public_access.tf.go
package builtin.openstack.compute.openstack0002

import rego.v1

deny contains res if {
	some rule in input.openstack.compute.firewall.allowrules
	is_rule_enabled(rule)
	rule.destination.value == ""
	res := result.new("Firewall rule does not restrict destination address internally.", rule)
}

deny contains res if {
	some rule in input.openstack.compute.firewall.allowrules
	is_rule_enabled(rule)
	cidr.is_public(rule.destination.value)
	res := result.new("Firewall rule allows public egress.", rule.destination)
}

deny contains res if {
	some rule in input.openstack.compute.firewall.allowrules
	is_rule_enabled(rule)
	rule.source.value == ""
	res := result.new("Firewall rule does not restrict source address internally.", rule.source)
}

deny contains res if {
	some rule in input.openstack.compute.firewall.allowrules
	is_rule_enabled(rule)
	cidr.is_public(rule.source.value)
	res := result.new("Firewall rule allows public ingress.", rule.source)
}

is_rule_enabled(rule) := rule.enabled.value == true
