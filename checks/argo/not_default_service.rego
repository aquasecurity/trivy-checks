# METADATA
# title: "default ServiceAccount not allowed"
# description: "Ensure Workflow pods are not using the default serviceAccountName"
# scope: package
# custom:
#   id: 
#   avd_id: 
#   severity: HIGH 
#   provider: Kubernetes
#   short_code: default-serviceaccount-not-allowed 
#   recommended_action: "Default ServiceAccount not allowed"
package builtin.argowf

deny[msg] {
    input.kind == "Workflow"
    not input.spec.serviceAccountName
    msg := "Ensure Workflow pods are not using the default ServiceAccount" 
}

deny[msg] {
    input.kind == "Workflow"
    input.spec.serviceAccountName == "default"
    msg := "Ensure Workflow pods are not using the default ServiceAccount" 
}
