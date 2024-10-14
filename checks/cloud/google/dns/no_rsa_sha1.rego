# METADATA
# title: Zone signing should not use RSA SHA1
# description: |
#   RSA SHA1 is a weaker algorithm than SHA2-based algorithms such as RSA SHA256/512
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0012
#   avd_id: AVD-GCP-0012
#   provider: google
#   service: dns
#   severity: MEDIUM
#   short_code: no-rsa-sha1
#   recommended_action: Use RSA SHA512
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: dns
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dns_managed_zone#algorithm
#     good_examples: checks/cloud/google/dns/no_rsa_sha1.yaml
#     bad_examples: checks/cloud/google/dns/no_rsa_sha1.yaml
package builtin.google.dns.google0012

import rego.v1

deny contains res if {
	some zone in input.google.dns.managedzones
	some spec in zone.dnssec.defaultkeyspecs
	spec.algorithm.value == "rsasha1"
	res := result.new(
		sprintf("Zone uses %q key type with RSA SHA1 algorithm for signing.", [spec.algorithm.value]),
		spec.algorithm,
	)
}
