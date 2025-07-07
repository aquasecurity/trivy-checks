# METADATA
# title: Google Compute Network Using Default Firewall Rule
# description: |
#   Default "allow all" firewall rules should be removed or replaced with more specific rules, as they violate least privilege.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#name
# custom:
#   avd_id: AVD-GCP-0073
#   aliases:
#     - google-misc-google-compute-network-using-default-firewall-rule
#   provider: google
#   service: compute
#   severity: MEDIUM
#   short_code: google-compute-network-using
#   recommended_action: |
#     Remove default firewall rules that allow broad access. Implement custom firewall rules that only allow necessary traffic from specific sources.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/disable_default_firewall_rule.yaml
package builtin.google.compute.google0073

import rego.v1

# Default firewall rule name patterns used by Google Cloud
default_rule_patterns := {
	"default-allow-internal",
	"default-allow-ssh",
	"default-allow-rdp",
	"default-allow-icmp",
	"default-allow-https",
	"default-allow-http",
}

deny contains res if {
	some network in input.google.compute.networks
	some rule in network.firewall.ingressrules
	rule.firewallrule.isallow.value
	rule.firewallrule.enforced.value

	# Check for overly broad access patterns that indicate default rules
	is_likely_default_rule(rule)
	
	res := result.new(
		"Firewall rule allows overly broad access that may indicate default rule usage.",
		rule,
	)
}

# Detect patterns that suggest default firewall rules
is_likely_default_rule(rule) if {
	# Allow rule with broad internal network access (typical of default-allow-internal)
	some source in rule.sourceranges
	source.value == "10.128.0.0/9"
	some port in rule.firewallrule.ports
	port.fromport.value == 0
	port.toport.value == 65535
}