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
		"colon-separated secrets": {
			"data": {
				"config": "DB_PASSWORD:supersecret",
				"color": "blue",
			},
			"expected": 1,
			"expected_keys": {"DB_PASSWORD"},
		},
		"equals-separated secrets": {
			"data": {
				"env": "REDIS_MASTER_PASSWORD=abcd1234",
				"theme": "dark",
			},
			"expected": 1,
			"expected_keys": {"REDIS_MASTER_PASSWORD"},
		},
		"cm value with empty secret assignment": {
			"data": {
				"env": "REDIS_MASTER_PASSWORD=",
				"theme": "dark",
			},
			"expected": 0,
		},
		"cm value with shell interpolation": {
			"data": {"test": "REDIS_MASTER_PASSWORD=\"$(< \"${REDIS_MASTER_PASSWORD_FILE}\")\""},
			"expected": 0,
		},
		"cm value with env variable reference": {
			"data": {"test": "DB_PASSWORD=${DB_PASSWORD}"},
			"expected": 0,
		},
		"cm value with template syntax": {
			"data": {"test": "REDIS_MASTER_PASSWORD={{ .Values.redis.password }}"},
			"expected": 0,
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
