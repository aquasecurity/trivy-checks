# METADATA
# title: An ingress db security group rule allows traffic from /0.
# description: |
#   Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/api/rdb/AuthorizeDBSecurityGroupIngress.htm
# custom:
#   id: AVD-NIF-0011
#   avd_id: AVD-NIF-0011
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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_security_group#cidr_ip
#     good_examples: checks/cloud/nifcloud/rdb/no_public_ingress_db_sgr.tf.go
#     bad_examples: checks/cloud/nifcloud/rdb/no_public_ingress_db_sgr.tf.go
package builtin.nifcloud.rdb.nifcloud0011

import rego.v1

deny contains res if {
	some sg in input.nifcloud.rdb.dbsecuritygroups
	some c in sg.cidrs
	cidr.is_public(c.value)
	cidr.count_addresses(c.value) > 1
	res := result.new("DB Security group rule allows ingress from public internet.", c)
}
