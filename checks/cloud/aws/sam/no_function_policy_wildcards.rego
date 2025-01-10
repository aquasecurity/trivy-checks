# METADATA
# title: Function policies should avoid use of wildcards and instead apply the principle of least privilege
# description: |
#   You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-policies
# custom:
#   id: AVD-AWS-0114
#   avd_id: AVD-AWS-0114
#   provider: aws
#   service: sam
#   severity: HIGH
#   short_code: no-function-policy-wildcards
#   deprecated: true
#   recommended_action: Specify the exact permissions required, and to which resources they should apply instead of using wildcards.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   cloud_formation:
#     good_examples: checks/cloud/aws/sam/no_function_policy_wildcards.yaml
#     bad_examples: checks/cloud/aws/sam/no_function_policy_wildcards.yaml
package builtin.aws.sam.aws0114
