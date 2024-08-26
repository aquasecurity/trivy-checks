# METADATA
# title: Load balancer is exposed to the internet.
# description: |
#   There are many scenarios in which you would want to expose a load balancer to the wider internet, but this check exists as a warning to prevent accidental exposure of internal assets. You should ensure that this resource should be exposed publicly.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AWS-0053
#   avd_id: AVD-AWS-0053
#   provider: aws
#   service: elb
#   severity: HIGH
#   short_code: alb-not-public
#   recommended_action: Switch to an internal load balancer or add a tfsec ignore
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elb
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb
#     good_examples: checks/cloud/aws/elb/alb_not_public.tf.go
#     bad_examples: checks/cloud/aws/elb/alb_not_public.tf.go
package builtin.aws.elb.aws0053

import rego.v1

deny contains res if {
	some lb in input.aws.elb.loadbalancers
	lb.type.value != "gateway"
	lb.internal.value == false

	res := result.new("Load balancer is exposed publicly.", lb.internal)
}
