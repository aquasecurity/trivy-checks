# METADATA
# title: "Specific capabilities added"
# description: "According to pod security standard 'Capabilities', capabilities beyond the default set must not be added."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV-0022
#   long_id: kubernetes-no-non-default-capabilities
#   aliases:
#     - AVD-KSV-0022
#     - KSV022
#     - no-non-default-capabilities
#     - kubernetes-no-non-default-capabilities
#   severity: MEDIUM
#   recommended_action: "Do not set capabilities beyond the default set. Allowed capabilities: AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
#         - kind: replicaset
#         - kind: replicationcontroller
#         - kind: deployment
#         - kind: deploymentconfig
#         - kind: statefulset
#         - kind: daemonset
#         - kind: cronjob
#         - kind: job
#   examples: checks/kubernetes/specific_capabilities_added.yaml
package builtin.kubernetes.KSV022

import rego.v1

import data.lib.kubernetes

default failAdditionalCaps := false

# Add allowed capabilities to this set
allowed_caps := {
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
}

deny contains res if {
    container := kubernetes.containers[_]
    disallowed := {cap | cap := container.securityContext.capabilities.add[_]; not cap in allowed_caps}
    count(disallowed) > 0
    msg := sprintf(
        "Container '%s' of %s '%s' adds disallowed capabilities: %s",
        [container.name, kubernetes.kind, kubernetes.name, concat(", ", disallowed)],
    )
    res := result.new(msg, container)
}