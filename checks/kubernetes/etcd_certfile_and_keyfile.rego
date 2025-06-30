# METADATA
# title: "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate"
# description: "etcd should be configured to make use of TLS encryption for client connections."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0026
#   avd_id: AVD-KCV-0026
#   severity: LOW
#   short_code: ensure-etcd-certfile-and-etcd-keyfile-arguments-are-set-as-appropriate
#   recommended_action: "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate and key file parameters."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0026

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--etcd-certfile")
	kubernetes.command_has_flag(container.command, "--etcd-keyfile")
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--etcd-certfile")
	kubernetes.command_has_flag(container.args, "--etcd-certfile")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate"
	res := result.new(msg, container)
}
