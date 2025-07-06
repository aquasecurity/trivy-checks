# METADATA
# title: RDP Access Is Not Restricted
# description: |
#   Firewall rules should restrict RDP (TCP/3389) access to specific IP ranges. Open RDP access can be a security risk.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall
# custom:
#   id: AVD-GCP-0070
#   avd_id: AVD-GCP-0070
#   provider: google
#   service: compute
#   severity: HIGH
#   short_code: rdp-access-not-restricted
#   recommended_action: |
#     Restrict RDP (TCP port 3389) ingress in firewall rules. Only allow trusted IP ranges or use Identity-Aware Proxy for RDP access.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
# aliases:
#   - google-misc-rdp-access-is-not-restricted
package builtin.google.compute.google0070

import rego.v1

import data.lib.net

deny contains res if {
	some network in input.google.compute.networks
	count(object.get(network.firewall, "sourcetags", [])) == 0
	count(object.get(network.firewall, "targettags", [])) == 0

	some rule in network.firewall.ingressrules
	rule.firewallrule.isallow.value
	rule.firewallrule.enforced.value

	some source in rule.sourceranges
	net.cidr_allows_all_ips(source.value)

	some allow_rule in rule.firewallrule.allowrules
	allow_rule.protocol.value == "tcp"
	some port in allow_rule.ports
	port.value in ["3389", "3389-3389"]

	res := result.new(
		"Firewall rule allows unrestricted access to TCP port 3389 from any IP address.",
		source,
	)
}
