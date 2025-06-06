# METADATA
# title: "Ensure that the etcd data directory ownership is set to etcd:etcd"
# description: "Ensure that the etcd data directory ownership is set to etcd:etcd."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   avd_id: AVD-KCV-0059
#   severity: LOW
#   short_code: ensure-etcd-data-directory-ownership-set-etcd:etcd.
#   recommended_action: "Change the etcd data directory /var/lib/etcd ownership to etcd:etcd"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0059

import rego.v1

validate_data_dir_ownership(sp) := {"etcdDataDirectoryOwnership": ownership} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	ownership := sp.info.etcdDataDirectoryOwnership.values[_]
	not ownership == "etcd:etcd"
}

deny contains res if {
	output := validate_data_dir_ownership(input)
	msg := "Ensure that the etcd data directory ownership is set to etcd:etcd"
	res := result.new(msg, output)
}
