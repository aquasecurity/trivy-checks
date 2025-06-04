# METADATA
# title: URL annotation contains suspicious characters
# description: |
#   Annotations containing URLs with suspicious or non-standard characters may indicate attempts to obfuscate malicious behavior or bypass security controls.
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: KCV0094
#   avd_id: AVD-KCV-0094
#   severity: CRITICAL
#   short_code: suspicious-url-annotation
#   recommended_action: Review and sanitize URL annotations to remove suspicious characters.
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.kcv0094

import rego.v1

annotations_to_check := {"link.argocd.argoproj.io/external-link"} # https://argo-cd.readthedocs.io/en/release-3.0/user-guide/external-url/

regexp := "https?://[^\\s<>\"{}|^`\\\\\\r\\n]*[\\r\\n<>\"{}|^`\\\\][^\\s]*"

deny contains res if {
	some key in annotations_to_check
	annot := input.metadata.annotations[key]
	regex.match(regexp, annot)
	res := result.new(
		sprintf("Annotation '%s' contains suspicious characters", [key]),
		input.metadata,
	)
}

# https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.2/guide/ingress/annotations/#authentication
alb_oidc_annot_key := "alb.ingress.kubernetes.io/auth-idp-oidc"

deny contains res if {
	annot := input.metadata.annotations[alb_oidc_annot_key]
	d := json.unmarshal(substring(annot, 1, count(annot) - 2))
	some k
	lower(k) in {"issuer", "authorizationendpoint", "tokenendpoint", "userinfoendpoint"}
	regex.match(regexp, d[k])
	res := result.new(
		sprintf("Annotation '%s' contains suspicious characters", [alb_oidc_annot_key]),
		input.metadata,
	)
}
