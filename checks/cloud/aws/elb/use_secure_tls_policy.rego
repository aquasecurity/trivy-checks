# METADATA
# title: An outdated SSL policy is in use by a load balancer.
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AWS-0047
#   long_id: aws-elb-use-secure-tls-policy
#   aliases:
#     - AVD-AWS-0047
#     - use-secure-tls-policy
#     - aws-elb-use-secure-tls-policy
#   provider: aws
#   service: elb
#   severity: CRITICAL
#   recommended_action: Use a more recent TLS/SSL policy for the load balancer
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elb
#             provider: aws
#   examples: checks/cloud/aws/elb/use_secure_tls_policy.yaml
package builtin.aws.elb.aws0047

import rego.v1

import data.lib.aws.tls_policies
import data.lib.cloud.value

deny contains res if {
	some lb in input.aws.elb.loadbalancers
	isManaged(lb)
	some listener in lb.listeners
	has_outdated_policy(listener)
	res := result.new("Listener uses an outdated TLS policy.", listener.tlspolicy)
}

# Listeners that do not terminate TLS have no policy.
has_outdated_policy(listener) if {
	value.is_not_empty(listener.tlspolicy)
	not listener.tlspolicy.value in tls_policies.elb_secure_policies
}
