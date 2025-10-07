# METADATA
# title: "User resources should not be placed in kube-system namespace"
# description: "ensure that user resources are not placed in kube-system namespace"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/
# custom:
#   id: KSV037
#   avd_id: AVD-KSV-0037
#   aliases:
#     - no-user-pods-in-system-namespace
#   severity: MEDIUM
#   short_code: no-user-resources-in-system-namespace
#   recommended_action: "Deploy the user resources into a designated namespace which is not kube-system."
#   input:
#     selector:
#     - type: kubernetes
#   examples: checks/kubernetes/protect_core_components_namespace.yaml
package builtin.kubernetes.KSV037

import rego.v1

import data.lib.kubernetes

systemNamespaceInUse(metadata, spec) if {
	kubernetes.namespace == "kube-system"
	not core_component(metadata, spec)
}

core_component(metadata, spec) if {
	kubernetes.has_field(metadata.labels, "tier")
	metadata.labels.tier == "control-plane"
	kubernetes.has_field(spec, "priorityClassName")
	spec.priorityClassName == "system-node-critical"
	kubernetes.has_field(metadata.labels, "component")
	coreComponentLabels := ["kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"]
	metadata.labels.component = coreComponentLabels[_]
}

deny contains res if {
	systemNamespaceInUse(input.metadata, input.spec)
	msg := sprintf("%s '%s' should not be set with 'kube-system' namespace", [kubernetes.kind, kubernetes.name])
	res := result.new(msg, input.spec)
}
