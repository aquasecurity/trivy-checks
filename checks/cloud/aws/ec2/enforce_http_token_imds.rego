# METADATA
# title: aws_instance should activate session tokens for Instance Metadata Service.
# description: |
#   IMDS v2 (Instance Metadata Service) introduced session authentication tokens which improve security when talking to IMDS.
#
#   By default <code>aws_instance</code> resource sets IMDS session auth tokens to be optional.
#
#   To fully protect IMDS you need to enable session tokens by using <code>metadata_options</code> block and its <code>http_tokens</code> variable set to <code>required</code>.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service
# custom:
#   id: AVD-AWS-0028
#   avd_id: AVD-AWS-0028
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: enforce-http-token-imds
#   recommended_action: Enable HTTP token requirement for IMDS
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options
#     good_examples: checks/cloud/aws/ec2/enforce_http_token_imds.tf.go
#     bad_examples: checks/cloud/aws/ec2/enforce_http_token_imds.tf.go
package builtin.aws.ec2.aws0028

import rego.v1

deny contains res if {
	some instance in input.aws.ec2.instances
	instance.metadataoptions.httptokens.value != "required"
	instance.metadataoptions.httpendpoint.value != "disabled"
	res := result.new(
		"Instance does not require IMDS access to require a token.",
		instance.metadataoptions.httptokens,
	)
}
