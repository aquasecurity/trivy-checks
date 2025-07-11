# METADATA
# title: "Ensure that the --cert-file and --key-file arguments are set as appropriate"
# description: "Configure TLS encryption for the etcd service."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0042
#   aliases:
#     - AVD-KCV-0042
#     - KCV0042
#     - Ensure-cert-file-and-key-file-arguments-are-set-as-appropriate
#   long_id: kubernetes-Ensure-cert-file-and-key-file-arguments-are-set-as-appropriate
#   severity: LOW
#   recommended_action: "Follow the etcd service documentation and configure TLS encryption. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0042

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--cert-file")
	kubernetes.command_has_flag(container.command, "--key-file")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--cert-file")
	kubernetes.command_has_flag(container.args, "--key-file")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not checkFlag(container)
	msg := "Ensure that the --cert-file and --key-file arguments are set as appropriate"
	res := result.new(msg, container)
}
