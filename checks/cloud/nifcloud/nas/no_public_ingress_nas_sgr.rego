# METADATA
# title: A security group rule should not allow unrestricted ingress from any IP address.
# description: |
#   Opening up ports to allow connections from the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/api/nas/AuthorizeNASSecurityGroupIngress.htm
# custom:
#   id: AVD-NIF-0014
#   avd_id: AVD-NIF-0014
#   aliases:
#     - nifcloud-nas-no-public-ingress-nas-sgr
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
#   examples: checks/cloud/nifcloud/nas/no_public_ingress_nas_sgr.yaml
package builtin.nifcloud.nas.nifcloud0014

import rego.v1

import data.lib.net

deny contains res if {
	some sg in input.nifcloud.nas.nassecuritygroups
	some c in sg.cidrs
	net.cidr_allows_all_ips(c.value)
	res := result.new("Security group rule allows unrestricted ingress from any IP address.", c)
}
