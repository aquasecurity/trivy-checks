# METADATA
# title: "ensure workflow pods are running as non root"
# description: "Ensure Workflow pods are running as non root"
# scope: package
# related_resources:
# - https://argo-workflows.readthedocs.io/en/latest/workflow-pod-security-context/
# custom:
#   id: ID002
#   avd_id: AVD-ARGOWF-0002
#   severity: HIGH 
#   provider: Kubernetes
#   short_code: non-root-argowf
#   recommended_action: "Ensure pods are running as non root"
package custom.argowf.ID002

deny[msg] {
    input.kind == "Workflow"
    not input.spec.securityContext.runAsNonRoot
    msg = "Workflow should not run as root and securityContext.runAsNonRoot for the workflow should be set to true." 
}

deny[msg] {
    input.kind == "Workflow"
    input.spec.securityContext.runAsNonRoot != true
    msg = "Workflow should not run as root and securityContext.runAsNonRoot for the workflow should be set to true." 
}