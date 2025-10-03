# METADATA
# title: Gatekeeper repo reference is ambiguously open-ended
# description: A Gatekeeper policy that references image repositories for prefix-matching is using open-ended and ambiguous pattern, and can potentially match unintended repositories.
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: KSV-0124
#   avd_id: AVD-KSV-0124
#   severity: HIGH
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV0124

import rego.v1

relevant_resource if {
	input.apiVersion == "constraints.gatekeeper.sh/v1beta1"
	input.kind == "K8sAllowedRepos"
}

deny contains res if {
	relevant_resource
	some repo in input.spec.parameters.repos
	not contains(repo, "/")
	not contains(repo, ":")
	res := result.new(
		"open-ended repository reference in prefix match",
		input.spec.parameters,
	)
}

deny contains res if {
	relevant_resource
	some repo in input.spec.parameters.repos
	parts := split(repo, "/")
	parts[0] == "docker.io"
	count(parts) <= 2
	res := result.new(
		"open-ended repository reference in prefix match",
		input.spec.parameters,
	)
}
