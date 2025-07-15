# METADATA
# title: Disable Default Firewall Rules
# description: |
#   Ensures that Google Cloud's default firewall rules are disabled, as they may be overly permissive and pose security risks.
#   The default network comes with pre-populated firewall rules that allow broad access and should be replaced with more restrictive custom rules.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall
#   - https://cloud.google.com/firewall/docs/firewalls#more_rules_default_vpc
# custom:
#   id: GCP-0073
#   aliases:
#     - AVD-GCP-0073
#     - google-compute-disable-default-firewall-rules
#   long_id: google-compute-disable-default-firewall-rules
#   provider: google
#   service: compute
#   severity: MEDIUM
#   recommended_action: Replace default firewall rules with custom, more restrictive rules appropriate for your security requirements
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/disable_default_firewall_rule.yaml
package builtin.google.compute.google0073

import rego.v1

import data.lib.net

deny contains res if {
	some network in input.google.compute.networks
	some rule in network.firewall.ingressrules
	rule.firewallrule.isallow.value
	rule.firewallrule.enforced.value

	is_default_firewall_rule(rule)

	res := result.new(
		"Default firewall rule should be disabled and replaced with more restrictive rules.",
		rule,
	)
}

is_default_firewall_rule(rule) if {
	some source in rule.sourceranges

	# Check for default-allow-internal pattern (10.128.0.0/9)
	source.value == "10.128.0.0/9"
}

is_default_firewall_rule(rule) if {
	some source in rule.sourceranges

	# Check for default public access rules (SSH, RDP, ICMP from anywhere)
	net.cidr_allows_all_ips(source.value)
}
