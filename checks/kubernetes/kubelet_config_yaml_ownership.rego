# METADATA
# title: "If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root "
# description: "Ensure that if the kubelet refers to a configuration file with the --config argument, that file is owned by root:root."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0078
#   aliases:
#     - AVD-KCV-0078
#     - KCV0078
#     - ensure-kubeconfig-kubelet-config.yaml-ownership-set-root:root
#   long_id: kubernetes-ensure-kubeconfig-kubelet-config.yaml-ownership-set-root:root
#   severity: HIGH
#   recommended_action: "Change the kubelet config.yaml file ownership to root:root"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0078

import rego.v1

types := ["master", "worker"]

validate_kubelet_config_yaml_ownership(sp) := {"kubeletConfigYamlConfigurationFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletConfigYamlConfigurationFileOwnership) > 0
	violation := {ownership | ownership = sp.info.kubeletConfigYamlConfigurationFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_kubelet_config_yaml_ownership(input)
	msg := "Ensure that if the kubelet refers to a configuration file with the --config argument, that file is owned by root:root."
	res := result.new(msg, output)
}
