# METADATA
# title: "Ensure ingress-nginx annotations are secure"
# description: "Check for insecure annotations in ingress-nginx configurations."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://github.com/kubernetes/kubernetes/issues/131008
# - https://github.com/kubernetes/kubernetes/issues/131007
# - https://github.com/kubernetes/kubernetes/issues/131006
# custom:
#   id: KCV0093
#   avd_id: AVD-KCV-0093
#   severity: CRITICAL
#   short_code: insecure-ingress-nginx
#   recommended_action: "Ensure that ingress-nginx annotations do not contain suspicious characters."
#   input:
#     selector:
#     - type: kubernetes
#   examples: checks/kubernetes/insecure_ingress_nginx.yaml

package builtin.kubernetes.kcv0093

import data.lib.kubernetes
import rego.v1

annotation_keys := {
	"auth_url": "nginx.ingress.kubernetes.io/auth-url",
	"auth_tls_match_cn": "nginx.ingress.kubernetes.io/auth-tls-match-cn",
	"mirror_target": "nginx.ingress.kubernetes.io/mirror-target",
	"mirror_host": "nginx.ingress.kubernetes.io/mirror-host",
}

regex_patterns := {
	"url": "https?://[^\\s<>\"{}|^`\\\\\\r\\n]*[\\r\\n<>\"{}|^`\\\\][^\\s]*",
	"cn": "CN=.*[\\r\\n#{};|].*",
}

suspicious_annotation := {key |
	lower(input.kind) == "ingress"
	kubernetes.has_field(input.spec, "ingressClassName")
	lower(input.spec.ingressClassName) == "nginx"
	key := annotation_keys[_]
	regex.match(regex_patterns[_], input.metadata.annotations[key])
}

deny contains res if {
	key := suspicious_annotation[_]
	res := result.new(sprintf("Pod has a %s annotation containing suspicious characters", [key]), input.metadata)
}
