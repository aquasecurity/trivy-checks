# METADATA
# title: SSL policies should enforce secure versions of TLS
# description: |
#   TLS versions prior to 1.2 are outdated and insecure. You should use 1.2 as aminimum version.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0039
#   avd_id: AVD-GCP-0039
#   provider: google
#   service: compute
#   severity: CRITICAL
#   short_code: use-secure-tls-policy
#   recommended_action: Enforce a minimum TLS version of 1.2
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/use_secure_tls_policy.yaml
package builtin.google.compute.google0039

import rego.v1

tls_v_1_2 := "TLS_1_2"

deny contains res if {
	some policy in input.google.compute.sslpolicies
	policy.minimumtlsversion.value != tls_v_1_2
	res := result.new("TLS policy does not specify a minimum of TLS 1.2", policy.minimumtlsversion)
}
