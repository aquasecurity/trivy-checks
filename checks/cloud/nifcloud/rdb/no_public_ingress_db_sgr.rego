# METADATA
# title: A security group rule should not allow unrestricted ingress traffic from any IP address.
# description: |
#   Opening up ports to allow connections from the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/api/rdb/AuthorizeDBSecurityGroupIngress.htm
# custom:
#   id: AVD-NIF-0011
#   avd_id: AVD-NIF-0011
#   aliases:
#     - nifcloud-rdb-no-public-ingress-db-sgr
#   provider: nifcloud
#   service: rdb
#   severity: CRITICAL
#   short_code: no-public-ingress-db-sgr
#   recommended_action: Set a more restrictive cidr range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rdb
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/rdb/no_public_ingress_db_sgr.yaml
package builtin.nifcloud.rdb.nifcloud0011

import rego.v1

import data.lib.net

deny contains res if {
	some sg in input.nifcloud.rdb.dbsecuritygroups
	some c in sg.cidrs
	net.cidr_allows_all_ips(c.value)
	res := result.new("Security group rule allows unrestricted ingress from any IP address.", c)
}
