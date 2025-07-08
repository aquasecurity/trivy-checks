# METADATA
# title: State machine policies should avoid use of wildcards and instead apply the principle of least privilege
# description: |
#   You should use the principle of least privilege when defining your IAM policies.
#   This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - "https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-policies"
# custom:
#   id: AWS-0120
#   aliases:
#     - AVD-AWS-0120
#     - no-state-machine-policy-wildcards
#   long_id: aws-sam-no-state-machine-policy-wildcards
#   provider: aws
#   service: sam
#   severity: HIGH
#   deprecated: true
#   recommended_action: Specify the exact permissions required, and to which resources they should apply instead of using wildcards.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   examples: checks/cloud/aws/sam/no_state_machine_policy_wildcards.yaml
package builtin.aws.sam.aws0120
