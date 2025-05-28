# METADATA
# title: "Selector usage in network policies"
# description: "ensure that network policies selectors are applied to pods or namespaces to restricted ingress and egress traffic within the pod network"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/
# custom:
#   id: KSV038
#   avd_id: AVD-KSV-0038
#   severity: MEDIUM
#   short_code: selector-usage-in-network-policies
#   recommended_action: "create network policies and ensure that pods are selected using the podSelector and/or the namespaceSelector options"
#   input:
#     selector:
#     - type: kubernetes
#   examples: checks/kubernetes/selector_usage_in_network_policies.yaml
package builtin.kubernetes.KSV038

import rego.v1

import data.lib.kubernetes

hasSelector(spec) if {
	kubernetes.has_field(spec, "podSelector")
	kubernetes.has_field(spec.podSelector, "matchLabels")
}

hasSelector(spec) if {
	kubernetes.has_field(spec, "namespaceSelector")
}

hasSelector(spec) if {
	kubernetes.has_field(spec, "podSelector")
}

hasSelector(spec) if {
	kubernetes.has_field(spec, "ingress")
	kubernetes.has_field(spec.ingress[_], "from")
	kubernetes.has_field(spec.ingress[_].from[_], "namespaceSelector")
}

hasSelector(spec) if {
	kubernetes.has_field(spec, "ingress")
	kubernetes.has_field(spec.ingress[_], "from")
	kubernetes.has_field(spec.ingress[_].from[_], "podSelector")
}

hasSelector(spec) if {
	kubernetes.has_field(spec, "egress")
	kubernetes.has_field(spec.egress[_], "to")
	kubernetes.has_field(spec.egress[_].to[_], "podSelector")
}

hasSelector(spec) if {
	kubernetes.has_field(spec, "egress")
	kubernetes.has_field(spec.egress[_], "to")
	kubernetes.has_field(spec.egress[_].to[_], "namespaceSelector")
}

hasSelector(spec) if {
	kubernetes.spec.podSelector == {}
	"Egress" in spec.policyType
}

hasSelector(spec) if {
	kubernetes.spec.podSelector == {}
	"Ingress" in spec.policyType
}

deny contains res if {
	lower(kubernetes.kind) == "networkpolicy"
	not hasSelector(input.spec)
	msg := "Network policy should uses podSelector and/or the namespaceSelector to restrict ingress and egress traffic within the Pod network"
	res := result.new(msg, input.spec)
}
