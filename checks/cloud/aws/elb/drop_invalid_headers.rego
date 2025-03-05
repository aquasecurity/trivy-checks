# METADATA
# title: Load balancers should drop invalid headers
# description: |
#   Passing unknown or invalid headers through to the target poses a potential risk of compromise.
#   By setting drop_invalid_header_fields to true, anything that does not conform to well known, defined headers will be removed by the load balancer.
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
#   examples: checks/cloud/aws/elb/drop_invalid_headers.yaml
package builtin.aws.elb.aws0052

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some lb in input.aws.elb.loadbalancers
	isManaged(lb)
	lb.type.value == "application"
	not lb.dropinvalidheaderfields.value
	res := result.new(
		"Application load balancer is not set to drop invalid headers.",
		metadata.obj_by_path(lb, ["dropinvalidheaderfields"]),
	)
}
