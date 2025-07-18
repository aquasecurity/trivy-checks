# METADATA
# title: "Protecting Pod service account tokens"
# description: "ensure that Pod specifications disable the secret token being mounted by setting automountServiceAccountToken: false"
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#serviceaccount-admission-controller
# custom:
#   id: KSV-0036
#   aliases:
#     - AVD-KSV-0036
#     - KSV036
#     - no-auto-mount-service-token
#   long_id: kubernetes-no-auto-mount-service-token
#   severity: MEDIUM
#   recommended_action: "Disable the mounting of service account secret token by setting automountServiceAccountToken to false"
#   input:
#     selector:
#       - type: kubernetes
#   examples: checks/kubernetes/protecting_pod_service_account_tokens.yaml
package builtin.kubernetes.KSV036

import rego.v1

import data.lib.kubernetes
import data.lib.utils

mountServiceAccountToken(spec) if {
	utils.has_key(spec, "automountServiceAccountToken")
	spec.automountServiceAccountToken == true
}

# if there is no automountServiceAccountToken spec, check on volumeMount in containers. Service Account token is mounted on /var/run/secrets/kubernetes.io/serviceaccount
mountServiceAccountToken(spec) if {
	not utils.has_key(spec, "automountServiceAccountToken")
	"/var/run/secrets/kubernetes.io/serviceaccount" == kubernetes.containers[_].volumeMounts[_].mountPath
}

deny contains res if {
	mountServiceAccountToken(input.spec)
	msg := kubernetes.format(sprintf("Container of %s '%s' should set 'spec.automountServiceAccountToken' to false", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
