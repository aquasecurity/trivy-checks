# METADATA
# title: Delete verified record
# description: |
#   Removing verified record of TXT auth the risk that
#
#   If the authentication record remains, anyone can register the zone
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/guide/dns/zone_new.htm
# custom:
#   id: AVD-NIF-0007
#   avd_id: AVD-NIF-0007
#   provider: nifcloud
#   service: dns
#   severity: CRITICAL
#   short_code: remove-verified-record
#   recommended_action: Remove verified record
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: dns
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/dns/remove_verified_record.yaml
package builtin.nifcloud.dns.nifcloud0007

import rego.v1

deny contains res if {
	some record in input.nifcloud.dns.records
	record.type.value == "TXT"
	startswith(record.record.value, "nifty-dns-verify=")
	res := result.new("Authentication TXT record exists.", record)
}
