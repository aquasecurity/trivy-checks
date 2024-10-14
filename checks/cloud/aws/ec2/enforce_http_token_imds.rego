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
#     good_examples: checks/cloud/aws/ec2/enforce_http_token_imds.yaml
#     bad_examples: checks/cloud/aws/ec2/enforce_http_token_imds.yaml
package builtin.aws.ec2.aws0028

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some instance in input.aws.ec2.instances
	tokens_is_not_required(instance)
	endpoint_is_not_disabled(instance)
	res := result.new(
		"Instance does not require IMDS access to require a token.",
		metadata.obj_by_path(instance, ["metadataoptions", "httptokens"]),
	)
}

tokens_is_not_required(instance) if value.is_not_equal(instance.metadataoptions.httptokens, "required")

tokens_is_not_required(instance) if not instance.metadataoptions.httptokens

endpoint_is_not_disabled(instance) if value.is_not_equal(instance.metadataoptions.httpendpoint, "disabled")

endpoint_is_not_disabled(instance) if not instance.metadataoptions.httpendpoint
