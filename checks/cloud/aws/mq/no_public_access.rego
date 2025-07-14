# METADATA
# title: Ensure MQ Broker is not publicly exposed
# description: |
#   Public access of the MQ broker should be disabled and only allow routes to applications that require access.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html#prefer-brokers-without-public-accessibility
# custom:
#   id: AWS-0072
#   aliases:
#     - AVD-AWS-0072
#     - no-public-access
#   long_id: aws-mq-no-public-access
#   provider: aws
#   service: mq
#   severity: HIGH
#   recommended_action: Disable public access when not required
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: mq
#             provider: aws
#   examples: checks/cloud/aws/mq/no_public_access.yaml
package builtin.aws.mq.aws0072

import rego.v1

deny contains res if {
	some broker in input.aws.mq.brokers
	broker.publicaccess.value == true

	res := result.new("Broker has public access enabled.", broker.publicaccess)
}
