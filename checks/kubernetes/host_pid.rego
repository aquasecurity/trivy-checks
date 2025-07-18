# METADATA
# title: "Access to host PID"
# description: "Sharing the host’s PID namespace allows visibility on host processes, potentially leaking information such as environment variables and configuration."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV-0010
#   aliases:
#     - AVD-KSV-0010
#     - KSV010
#     - no-host-pid
#   long_id: kubernetes-no-host-pid
#   severity: HIGH
#   recommended_action: "Do not set 'spec.template.spec.hostPID' to true."
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: pod
#           - kind: replicaset
#           - kind: replicationcontroller
#           - kind: deployment
#           - kind: deploymentconfig
#           - kind: statefulset
#           - kind: daemonset
#           - kind: cronjob
#           - kind: job
#   examples: checks/kubernetes/host_pid.yaml
package builtin.kubernetes.KSV010

import rego.v1

import data.lib.kubernetes

default failHostPID := false

# failHostPID is true if spec.hostPID is set to true (on all controllers)
failHostPID if {
	kubernetes.host_pids[_] == true
}

deny contains res if {
	failHostPID
	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostPID' to true", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
