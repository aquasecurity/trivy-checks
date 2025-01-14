# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: kubernetes
#     - type: rbac
package lib.k8s_sec_context

import rego.v1

# Some fields are present in both SecurityContext and PodSecurityContext.
# When both are set, the values in SecurityContext take precedence.
# See https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.32/#securitycontext-v1-core
resolve_container_sec_context(pod, container) := object.union(
	_inherited_sec_ctx(pod),
	object.get(container, "securityContext", {}),
)

_inherited_sec_ctx(pod) := {k: v |
	ctx := object.get(pod, ["spec", "securityContext"], {})
	some k, v in ctx
	k in _inherited_sec_ctx_fields
}

_inherited_sec_ctx_fields := {
	"runAsGroup",
	"runAsNonRoot",
	"runAsUser",
	"seLinuxOptions",
	"seccompProfile",
	"windowsOptions",
}
