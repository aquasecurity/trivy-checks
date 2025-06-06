# METADATA
# title: "Ensure that the --hostname-override argument is not set"
# description: "Do not override node hostnames."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   avd_id: AVD-KCV-0086
#   severity: HIGH
#   short_code: ensure-hostname-override-argument-not-set
#   recommended_action: "Edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and remove the --hostname-override argument"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0086

import rego.v1

types := ["master", "worker"]

validate_kubelet_hostname_override_set(sp) := {"kubeletHostnameOverrideArgumentSet": hostname_override} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletHostnameOverrideArgumentSet.values) > 0
	hostname_override = sp.info.kubeletHostnameOverrideArgumentSet.values
}

deny contains res if {
	output := validate_kubelet_hostname_override_set(input)
	msg := "Ensure that the --hostname-override argument is not set"
	res := result.new(msg, output)
}
