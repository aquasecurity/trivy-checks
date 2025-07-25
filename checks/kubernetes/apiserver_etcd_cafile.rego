# METADATA
# title: "Ensure that the --etcd-cafile argument is set as appropriate"
# description: "etcd should be configured to make use of TLS encryption for client connections."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0029
#   aliases:
#     - AVD-KCV-0029
#     - KCV0029
#     - ensure-etcd-cafile-argument-is-set-as-appropriate
#   long_id: kubernetes-ensure-etcd-cafile-argument-is-set-as-appropriate
#   severity: LOW
#   recommended_action: "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate authority file parameter."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0029

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--etcd-cafile")
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--etcd-cafile")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --etcd-cafile argument is set as appropriate"
	res := result.new(msg, container)
}
