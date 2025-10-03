# METADATA
# title: "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate"
# description: "etcd should be configured to make use of TLS encryption for peer connections."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0045
#   avd_id: AVD-KCV-0045
#   severity: LOW
#   short_code: ensure-peer-cert-file-and-peer-key-file-arguments-are-set-as-appropriate
#   recommended_action: "Follow the etcd service documentation and configure peer TLS encryption as appropriate for your etcd cluster. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0045

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--peer-cert-file")
	kubernetes.command_has_flag(container.command, "--peer-key-file")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--peer-cert-file")
	kubernetes.command_has_flag(container.args, "--peer-key-file")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not checkFlag(container)
	msg := "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate"
	res := result.new(msg, container)
}
