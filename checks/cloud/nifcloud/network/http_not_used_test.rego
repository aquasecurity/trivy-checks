package builtin.nifcloud.network.nifcloud0021_test

import rego.v1

import data.builtin.nifcloud.network.nifcloud0021 as check
import data.lib.test

test_deny_elastic_lb_with_http_protocol_on_global if {
	inp := build_elb_input({
		"networkinterfaces": [{"networkid": {"value": "net-COMMON_GLOBAL", "isvipnetwork": {"value": true}}}, {"networkid": {"value": "some-network"}}],
		"listeners": [{"protocol": {"value": "HTTP"}}],
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_elastic_lb_with_http_protocol_on_internal if {
	inp := build_elb_input({
		"networkinterfaces": [{"networkid": {"value": "some-network"}, "isvipnetwork": {"value": true}}],
		"listeners": [{"protocol": {"value": "HTTP"}}],
	})

	res := check.deny with input as inp
	res == set()
}

test_allow_elastic_lb_with_https_protocol_on_global if {
	inp := build_elb_input({
		"networkinterfaces": [{"networkid": {"value": "net-COMMON_GLOBAL"}, "isvipnetwork": {"value": true}}],
		"listeners": [{"protocol": {"value": "HTTPS"}}],
	})

	res := check.deny with input as inp
	res == set()
}

test_deny_lb_with_http_protocol if {
	inp := {"nifcloud": {"network": {"loadbalancers": [{"listeners": [{"protocol": {"value": "HTTP"}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_lb_with_https_protocol if {
	inp := {"nifcloud": {"network": {"loadbalancers": [{"listeners": [{"protocol": {"value": "HTTPS"}}]}]}}}

	res := check.deny with input as inp
	res == set()
}

build_elb_input(elb) := {"nifcloud": {"network": {"elasticloadbalancers": [elb]}}}
