# METADATA
# title: "Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers"
# description: "Ensure that the Kubelet is configured to only use strong cryptographic ciphers."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0092
#   avd_id: AVD-KCV-0092
#   severity: CRITICAL
#   short_code: ensure-Kubelet-only-makes-use-strong-cryptographic-ciphers
#   recommended_action: "If using a Kubelet config file, edit the file to set TLSCipherSuites"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0092

import rego.v1

types := ["master", "worker"]

strong_cryptographic := [
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"TLS_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_RSA_WITH_AES_128_GCM_SHA256",
]

validate_kubelet_only_use_strong_cryptographic(sp) := {"kubeletOnlyUseStrongCryptographic": only_use_strong_cryptographic} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	only_use_strong_cryptographic := sp.info.kubeletOnlyUseStrongCryptographic.values[_]
	not only_use_strong_cryptographic in strong_cryptographic
}

validate_kubelet_only_use_strong_cryptographic(sp) := {"kubeletOnlyUseStrongCryptographic": only_use_strong_cryptographic} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletOnlyUseStrongCryptographic.values) == 0
	only_use_strong_cryptographic = {}
}

deny contains res if {
	output := validate_kubelet_only_use_strong_cryptographic(input)
	msg := "Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers"
	res := result.new(msg, output)
}
