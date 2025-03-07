# METADATA
# title: A firewall rule should not allow unrestricted ingress from any IP address.
# description: |
#   Opening up ports to allow connections from the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/vpc/docs/using-firewalls
# custom:
#   id: AVD-GCP-0027
#   avd_id: AVD-GCP-0027
#   provider: google
#   service: compute
#   severity: CRITICAL
#   short_code: no-public-ingress
#   recommended_action: Set a more restrictive cidr range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/no_public_ingress.yaml
package builtin.google.compute.google0027

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
	res := result.new(
		"Firewall rule allows unrestricted ingress from any IP address.",
		source,
	)
}
