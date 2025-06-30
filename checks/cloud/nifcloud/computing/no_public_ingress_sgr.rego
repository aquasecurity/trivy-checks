# METADATA
# title: A security group rule should not allow unrestricted ingress from any IP address.
# description: |
#   Opening up ports to allow connections from the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
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
#   aliases:
#     - nifcloud-computing-no-public-ingress-sgr
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
#   examples: checks/cloud/nifcloud/computing/no_public_ingress_sgr.yaml
package builtin.nifcloud.computing.nifcloud0001

import rego.v1

import data.lib.net

deny contains res if {
	some sg in input.nifcloud.computing.securitygroups
	some rule in sg.ingressrules
	net.cidr_allows_all_ips(rule.cidr.value)
	res := result.new(
		"Security group rule allows unrestricted ingress from any IP address.",
		rule.cidr,
	)
}
