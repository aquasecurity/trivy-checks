# METADATA
# title: Use of plain HTTP.
# description: |
#   Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.
#
#   You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/
# custom:
#   id: AVD-NIF-0021
#   avd_id: AVD-NIF-0021
#   provider: nifcloud
#   service: network
#   severity: CRITICAL
#   short_code: http-not-used
#   recommended_action: Switch to HTTPS to benefit from TLS security features
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb#protocol
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#load_balancer_port
#     good_examples: checks/cloud/nifcloud/network/http_not_used.tf.go
#     bad_examples: checks/cloud/nifcloud/network/http_not_used.tf.go
package builtin.nifcloud.network.nifcloud0021

import rego.v1

deny contains res if {
	some lb in input.nifcloud.network.loadbalancers
	some listener in lb.listeners
	listener.protocol.value == "HTTP"
	res := result.new("Listener for l4 load balancer does not use HTTPS.", listener.protocol)
}

deny contains res if {
	some elb in input.nifcloud.network.elasticloadbalancers
	is_public_lb(elb)
	some listener in elb.listeners
	listener.protocol.value == "HTTP"
	res := result.new("Listener for multi load balancer does not use HTTPS.", listener.protocol)
}

is_public_lb(lb) if {
	some ni in lb.networkinterfaces
	not is_private_network(ni)
}

is_private_network(network) if network.networkid.value != "net-COMMON_GLOBAL"

is_private_network(network) if network.isvipnetwork.value == false
