# METADATA
# title: IAM policy should avoid use of wildcards and instead apply the principle of least privilege
# description: |
#   You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
# custom:
#   id: AVD-AWS-0057
#   avd_id: AVD-AWS-0057
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: no-policy-wildcards
#   recommended_action: Specify the exact permissions required, and to which resources they should apply instead of using wildcards.
#   frameworks:
#     cis-aws-1.4:
#       - "1.16"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document
#     good_examples: checks/cloud/aws/iam/no_policy_wildcards.tf.go
#     bad_examples: checks/cloud/aws/iam/no_policy_wildcards.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/iam/no_policy_wildcards.cf.go
#     bad_examples: checks/cloud/aws/iam/no_policy_wildcards.cf.go
package builtin.aws.iam.aws0057

import rego.v1

cloudwatch_log_stream_resource_pattern := `^arn:aws:logs:.*:.+:log-group:.+:\*`

deny contains res if {
    some policy in input.aws.iam.policies
    statement := parse_statement(policy)
    some action in statement.Action
    contains(action, "*")
    message := sprintf("IAM policy document uses wildcarded action %q", [action])
    res := result.new(message, {}) # TODO: MetadataFromIamGo
}

deny contains res if {
    some policy in input.aws.iam.policies
    statement := parse_statement(policy)
    some resource in statement.Resource
    contains(resource, "*")
    action := "" # TODO iam.IsWildcardAllowed
    not is_object_key_contains_wildcard(resource)
    not regex.match(cloudwatch_log_stream_resource_pattern, resource)
    message := sprintf("IAM policy document uses sensitive action %q on wildcarded resource %q", [action, resource])
    res := result.new(message, {}) # TODO: MetadataFromIamGo
}

deny contains res if {
    some policy in input.aws.iam.policies
    statement := parse_statement(policy)
    statement.Principal.All == true # TODO: check if it's exported to Rego
    res := result.new("IAM policy document uses wildcarded principal.", {}) # TODO: MetadataFromIamGo
}

deny contains res if {
    some policy in input.aws.iam.policies
    statement := parse_statement(policy)
    some principal in statement.Principal.AWS
    contains(principal, "*")
    res := result.new("IAM policy document uses wildcarded principal.", {}) # TODO: MetadataFromIamGo
}

parse_statement(policy) := statement if {
  policy.builtin.value == false
  document := json.unmarshal(policy.document.value)
  some statement in document.Statement
  statement.Effect == "Allow"
}

is_object_key_contains_wildcard(key) if {
    arn_parts := split(key, ":")
    count(arn_parts) == 6
    arn_parts[2] == "s3"

    resource_parts := split(arn_parts[5], "/")
    count(resource_parts) == 2

    not contains(resource_parts[0], "*")
    contains(resource_parts[1], "*")
}
