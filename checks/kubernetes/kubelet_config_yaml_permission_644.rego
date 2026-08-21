# METADATA
# title: "If the kubelet config.yaml configuration file is being used validate permissions set to 644 or more restrictive"
# description: "Ensure that if the kubelet refers to a configuration file with the --config argument, that file has permissions of 644 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0095
#   long_id: kubernetes-ensure-kubelet-config.yaml--permissions-644-or-more-restrictive.
#   aliases:
#     - AVD-KCV-0095
#     - KCV0095
#     - ensure-kubelet-config.yaml--permissions-644-or-more-restrictive.
#     - kubernetes-ensure-kubelet-config.yaml--permissions-644-or-more-restrictive.
#   severity: HIGH
#   recommended_action: "Change the kubelet config yaml permissions to 644 or more restrictive if exist"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0095

import rego.v1

types := ["master", "worker"]

validate_kubelet_config_yaml_permission(sp) := {"kubeletConfigYamlConfigurationFilePermission": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletConfigYamlConfigurationFilePermission) > 0
	violation := {permission | permission = sp.info.kubeletConfigYamlConfigurationFilePermission.values[_]; permission > 644}
	count(violation) > 0
}

deny contains res if {
	output := validate_kubelet_config_yaml_permission(input)
	msg := "Ensure that if the kubelet refers to a configuration file with the --config argument, that file has permissions of 644 or more restrictive."
	res := result.new(msg, output)
}
