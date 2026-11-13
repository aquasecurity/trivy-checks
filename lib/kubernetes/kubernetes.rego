# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: kubernetes
#     - type: rbac
package lib.kubernetes

import rego.v1

import data.lib.k8s_sec_context

default is_gatekeeper := false

is_gatekeeper if {
	has_field(input, "review")
	has_field(input.review, "object")
}

object := input if {
	not is_gatekeeper
}

object := input.review.object if {
	is_gatekeeper
}

format(msg) := gatekeeper_format if {
	is_gatekeeper
	gatekeeper_format = {"msg": msg}
}

format(msg) := msg if {
	not is_gatekeeper
}

name := object.metadata.name

default namespace := "default"

namespace := object.metadata.namespace

kind := object.kind

roleBindingKinds := {"RoleBinding", "ClusterRolebinding"}

is_role_binding_kind if kind in roleBindingKinds

is_pod if {
	kind = "Pod"
}

is_cronjob if {
	kind = "CronJob"
}

default is_controller := false

api_version := object.apiVersion

is_controller if {
	kind = "Deployment"
}

is_controller if {
	api_version = "apps.openshift.io/v1"
	kind = "DeploymentConfig"
}

is_controller if {
	kind = "StatefulSet"
}

is_controller if {
	kind = "DaemonSet"
}

is_controller if {
	kind = "ReplicaSet"
}

is_controller if {
	kind = "ReplicationController"
}

is_controller if {
	kind = "Job"
}

split_image(image) := [image, "latest"] if {
	not contains(image, ":")
}

split_image(image) := [image_name, tag] if {
	[image_name, tag] = split(image, ":")
}

pod_containers(pod) := all_containers if {
	keys = {"containers", "initContainers"}
	all_containers = [c |
		keys[k]
		some container in pod.spec[k]
		c := json.patch(
			container,
			[{
				"op": "add",
				"path": "securityContext",
				"value": k8s_sec_context.resolve_container_sec_context(pod, container),
			}],
		)
	]
}

containers contains container if {
	pods[pod]
	all_containers = pod_containers(pod)
	container = all_containers[_]
}

containers contains container if {
	all_containers = pod_containers(object)
	container = all_containers[_]
}

pods contains pod if {
	is_pod
	pod = object
}

pods contains pod if {
	is_controller
	pod = object.spec.template
}

pods contains pod if {
	is_cronjob
	pod = object.spec.jobTemplate.spec.template
}

volumes contains volume if {
	pods[pod]
	volume = pod.spec.volumes[_]
}

dropped_capability(container, cap) if {
	container.securityContext.capabilities.drop[_] == cap
}

added_capability(container, cap) if {
	container.securityContext.capabilities.add[_] == cap
}

has_field(obj, field) if {
	obj[field]
}

no_read_only_filesystem(c) if {
	not has_field(c, "securityContext")
}

no_read_only_filesystem(c) if {
	has_field(c, "securityContext")
	not has_field(c.securityContext, "readOnlyRootFilesystem")
}

privilege_escalation_allowed(c) if {
	not has_field(c, "securityContext")
}

privilege_escalation_allowed(c) if {
	has_field(c, "securityContext")
	has_field(c.securityContext, "allowPrivilegeEscalation")
}

annotations contains annotation if {
	pods[pod]
	annotation = pod.metadata.annotations
}

host_ipcs contains host_ipc if {
	pods[pod]
	host_ipc = pod.spec.hostIPC
}

host_networks contains host_network if {
	pods[pod]
	host_network = pod.spec.hostNetwork
}

host_pids contains host_pid if {
	pods[pod]
	host_pid = pod.spec.hostPID
}

host_aliases contains host_alias if {
	pods[pod]
	host_alias = pod.spec
}

command_has_flag(command, flag) if {
	regex.match(flag, command[_])
}

is_controllermanager(container) if {
	regex.match("^(.*/)?kube-controller-manager$", container.command[0])
}

is_etcd(container) if {
	regex.match("^(.*/)?etcd$", container.command[0])
}

is_scheduler(container) if {
	regex.match("^(.*/)?kube-scheduler$", container.command[0])
}

is_apiserver(container) if {
	regex.match("^(.*/)?kube-apiserver$", container.command[0])
}

# API groups that serve the built-in resources referenced by RBAC checks.
# "" is the core group. Legacy groups such as extensions are kept because
# older manifests still grant access through them.
resource_api_groups := {
	"pods": {""},
	"pods/exec": {""},
	"pods/log": {""},
	"nodes/proxy": {""},
	"secrets": {""},
	"configmaps": {""},
	"services": {""},
	"endpoints": {""},
	"replicationcontrollers": {""},
	"users": {""},
	"groups": {""},
	"deployments": {"apps", "extensions"},
	"daemonsets": {"apps", "extensions"},
	"replicasets": {"apps", "extensions"},
	"statefulsets": {"apps"},
	"jobs": {"batch"},
	"cronjobs": {"batch"},
	"endpointslices": {"discovery.k8s.io"},
	"networkpolicies": {"networking.k8s.io", "extensions"},
	"ingresses": {"networking.k8s.io", "extensions"},
	"roles": {"rbac.authorization.k8s.io"},
	"rolebindings": {"rbac.authorization.k8s.io"},
	"clusterroles": {"rbac.authorization.k8s.io"},
	"clusterrolebindings": {"rbac.authorization.k8s.io"},
	"mutatingwebhookconfigurations": {"admissionregistration.k8s.io"},
	"validatingwebhookconfigurations": {"admissionregistration.k8s.io"},
}

# rule_grants is true if the RBAC rule grants any of the verbs on any of the
# resources. A resource only counts in its own API group, so a CRD with the
# same name in another group does not match.
rule_grants(rule, resources, verbs) if {
	some resource in rule.resources
	resource in resources
	some verb in rule.verbs
	verb in verbs
	some group in rule.apiGroups
	api_group_serves(group, resource)
}

# A resource missing from resource_api_groups matches only the "*" group.
api_group_serves("*", _)

api_group_serves(group, resource) if {
	group in resource_api_groups[resource]
}
