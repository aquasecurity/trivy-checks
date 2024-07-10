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
#   id: AVD-AWS-0130
#   avd_id: AVD-AWS-0130
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: enforce-launch-config-http-token-imds
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
#     good_examples: checks/cloud/aws/ec2/as_enforce_http_token_imds.tf.go
#     bad_examples: checks/cloud/aws/ec2/as_enforce_http_token_imds.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ec2/as_enforce_http_token_imds.cf.go
#     bad_examples: checks/cloud/aws/ec2/as_enforce_http_token_imds.cf.go
package builtin.aws.ec2.aws0130

import rego.v1

deny contains res if {
	some config in input.aws.ec2.launchconfigurations
	opts_do_not_require_token(config.metadataoptions)
	res := result.new(
		"Launch configuration does not require IMDS access to require a token",
		config.metadataoptions.httptokens,
	)
}

deny contains res if {
	some tpl in input.aws.ec2.launchtemplates
	opts_do_not_require_token(tpl.instance.metadataoptions)
	res := result.new(
		"Launch template does not require IMDS access to require a token",
		tpl.instance.metadataoptions.httptokens,
	)
}

opts_do_not_require_token(opts) if {
	opts.httptokens.value != "required"
	opts.httpendpoint.value != "disabled"
}
