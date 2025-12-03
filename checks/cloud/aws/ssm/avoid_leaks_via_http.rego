# METADATA
# title: Secrets should not be exfiltrated using Terraform HTTP data blocks
# description: |
#   The data.http block can be used to send secret data outside of the organisation.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://sprocketfox.io/xssfox/2022/02/09/terraformsupply/
# custom:
#   id: AVD-AWS-0134
#   avd_id: AVD-AWS-0134
#   provider: aws
#   service: ssm
#   severity: CRITICAL
#   short_code: avoid-leaks-via-http
#   deprecated: true
#   recommended_action: Remove this potential exfiltration HTTP request.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ssm
#             provider: aws
#   examples: checks/cloud/aws/ssm/avoid_leaks_via_http.yaml
package builtin.aws.ssm.aws0134
