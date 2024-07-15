package builtin.nifcloud.sslcertificate.nifcloud0006_test

import rego.v1

import data.builtin.nifcloud.sslcertificate.nifcloud0006 as check
import data.lib.test

test_allow_not_expired_certificate if {
	inp := {"nifcloud": {"sslcertificate": {"servercertificates": [{"expiration": {"value": time.format(time.now_ns() + 3600000000000)}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_expired_certificate if {
	inp := {"nifcloud": {"sslcertificate": {"servercertificates": [{"expiration": {"value": time.format(time.now_ns() - 3600000000000)}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
