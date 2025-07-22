# METADATA
# title: "Ensure that the etcd pod specification file ownership is set to root:root"
# description: "Ensure that the etcd pod specification file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0055
#   aliases:
#     - AVD-KCV-0055
#     - KCV0055
#     - ensure-etcd-pod-specification-ownership-set
#   severity: HIGH
#   short_code: ensure-etcd-pod-specification-ownership-set-root:root.
#   recommended_action: "Change the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0055

import rego.v1

validate_spec_ownership(sp) := {"kubeEtcdSpecFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.kubeEtcdSpecFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_spec_ownership(input)
	msg := "Ensure that the etcd pod specification file ownership is set to root:root"
	res := result.new(msg, output)
}
