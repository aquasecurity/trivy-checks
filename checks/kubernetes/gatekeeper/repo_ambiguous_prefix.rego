# METADATA
# title: Gatekeeper repo reference is ambiguously open-ended
# description: A Gatekeeper policy that references image repositories for prefix-matching is using open-ended and ambiguous pattern, and can potentially match unintended repositories.
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: KSV-0124
#   avdid: AVD-KSV-0124
#   severity: HIGH
package builtin.kubernetes.KSV0124
import rego.v1

relevan_resource if {
    input.apiVersion == "constraints.gatekeeper.sh/v1beta1"
    input.kind == "K8sAllowedRepos"
}

deny contains res if {
    relevan_resource
    some repo in input.spec.parameters.repos
    not contains(repo,"/")
    not contains(repo,":")
    res := result.new(
        "open-ended repository reference in prefix match",
        repo
    )
}

deny contains res if {
    relevan_resource
    some repo in input.spec.parameters.repos
    parts:=split(repo,"/")
    parts[0] == "docker.io"
    count(parts) <= 2
    res := result.new(
        "open-ended repository reference in prefix match",
        repo
    )
}


