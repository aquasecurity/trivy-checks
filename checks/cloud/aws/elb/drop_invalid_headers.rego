# METADATA
# title: Load balancers should drop invalid headers
# description: |
#   Passing unknown or invalid headers through to the target poses a potential risk of compromise.
#   By setting drop_invalid_header_fields to true, anything that doe not conform to well known, defined headers will be removed by the load balancer.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html
# custom:
#   id: AVD-AWS-0052
#   avd_id: AVD-AWS-0052
#   provider: aws
#   service: elb
#   severity: HIGH
#   short_code: drop-invalid-headers
#   recommended_action: Set drop_invalid_header_fields to true
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elb
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#drop_invalid_header_fields
#     good_examples: checks/cloud/aws/elb/drop_invalid_headers.tf.go
#     bad_examples: checks/cloud/aws/elb/drop_invalid_headers.tf.go
package builtin.aws.elb.aws0052

import rego.v1

deny contains res if {
	some lb in input.aws.elb.loadbalancers
	lb.type.value == "application"
	lb.dropinvalidheaderfields.value == false
	res := result.new("Application load balancer is not set to drop invalid headers.", lb.dropinvalidheaderfields)
}
