# METADATA
# title: Delete expired SSL certificates
# description: |
#   Removing expired SSL/TLS certificates eliminates the risk that an invalid certificate will be
#
#   deployed accidentally to a resource such as NIFCLOUD Load Balancer(L4LB), which candamage the
#
#   credibility of the application/website behind the L4LB. As a best practice, it is
#
#   recommended to delete expired certificates.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/help/ssl/del.htm
# custom:
#   id: NIF-0006
#   aliases:
#     - AVD-NIF-0006
#     - remove-expired-certificates
#   long_id: nifcloud-sslcertificate-remove-expired-certificates
#   provider: nifcloud
#   service: ssl-certificate
#   severity: LOW
#   recommended_action: Remove expired certificates
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sslcertificate
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/sslcertificate/remove_expired_certificates.yaml
package builtin.nifcloud.sslcertificate.nifcloud0006

import rego.v1

deny contains res if {
	some cert in input.nifcloud.sslcertificate.servercertificates
	time.parse_rfc3339_ns(cert.expiration.value) - time.now_ns() <= 0
	res := result.new("Certificate has expired.", cert)
}
