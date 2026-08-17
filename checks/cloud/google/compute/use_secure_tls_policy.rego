# METADATA
# title: SSL policies should enforce secure versions of TLS
# description: |
#   TLS versions prior to 1.2 are outdated and insecure. You should use 1.2 as aminimum version.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0039
#   long_id: google-compute-use-secure-tls-policy
#   aliases:
#     - AVD-GCP-0039
#     - use-secure-tls-policy
#     - google-compute-use-secure-tls-policy
#   provider: google
#   service: compute
#   severity: CRITICAL
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

import data.lib.cloud.value

allowed_tls_versions := {"TLS_1_2", "TLS_1_3"}

deny contains res if {
	some policy in input.google.compute.sslpolicies
	value.is_known(policy.minimumtlsversion)
	not policy.minimumtlsversion.value in allowed_tls_versions
	res := result.new("TLS policy does not specify a minimum of TLS 1.2", policy.minimumtlsversion)
}
