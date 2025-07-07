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
#   id: AWS-0057
#   aliases:
#     - AVD-AWS-0057
#     - no-policy-wildcards
#   long_id: aws-iam-no-policy-wildcards
#   provider: aws
#   service: iam
#   severity: HIGH
#   deprecated: true
#   recommended_action: Specify the exact permissions required, and to which resources they should apply instead of using wildcards.
#   frameworks:
#     default:
#       - null
#     cis-aws-1.4:
#       - "1.16"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
#   examples: checks/cloud/aws/iam/no_policy_wildcards.yaml
package builtin.aws.iam.aws0057
