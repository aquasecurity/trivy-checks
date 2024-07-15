package builtin.digitalocean.spaces.digitalocean0006_test

import rego.v1

import data.builtin.digitalocean.spaces.digitalocean0006 as check
import data.lib.test

test_allow_acl_private_for_bucket if {
	inp := {"digitalocean": {"spaces": {"buckets": [{"acl": {"value": "private"}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_acl_public_read_for_bucket if {
	inp := {"digitalocean": {"spaces": {"buckets": [{"acl": {"value": "public-read"}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_private_acl_for_object if {
	inp := {"digitalocean": {"spaces": {"buckets": [{"objects": [
		{"acl": {"value": "private"}},
		{"acl": {"value": "aws-exec-read"}},
	]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_public_read_acl_for_object if {
	inp := {"digitalocean": {"spaces": {"buckets": [{"objects": [{"acl": {"value": "public-read"}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
