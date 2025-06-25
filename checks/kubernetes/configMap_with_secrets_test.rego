package builtin.kubernetes.KSV0109_test

import data.builtin.kubernetes.KSV0109 as check
import data.lib.test

import rego.v1

test_detect_secret[name] if {
	some name, tc in {
		"happy": {
			"data": {
				"color.good": "blue",
				"color.bad": "yellow",
			},
			"expected": 0,
		},
		"cm keys with sensitive values": {
			"data": {
				"password": "password123",
				"secretkey": "test",
			},
			"expected": 1,
			"expected_keys": {"password", "secretkey"},
		},
	}

	inp := {
		"apiVersion": "v1",
		"kind": "ConfigMap",
		"metadata": {"name": "test"},
		"data": tc.data,
	}

	res := check.deny with input as inp
	test.assert_count(res, tc.expected)
	assert_message(res, tc)
}

assert_message(res, tc) if {
	tc.expected > 0
	expected_message := sprintf(
		"ConfigMap 'test' in 'default' namespace stores secrets in key(s) or value(s) '%v'",
		[tc.expected_keys],
	)
	test.assert_equal_message(expected_message, res)
} else if {
	tc.expected == 0
}
