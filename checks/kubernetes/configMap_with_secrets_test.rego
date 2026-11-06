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
		"equals-separated secret with colon in value": {
			"data": {"settings": "log_level=debug\npassword=synthetic:123"},
			"expected": 1,
			"expected_keys": {"password"},
		},
		"colon-separated secret with equals in value": {
			"data": {"settings": "password: synthetic=123"},
			"expected": 1,
			"expected_keys": {"password"},
		},
		"secret with url value": {
			"data": {"env": "TOKEN=https://example.com:8443/token"},
			"expected": 1,
			"expected_keys": {"TOKEN"},
		},
		"cm value with env variable reference after space": {
			"data": {"settings": "password: ${DB_PASSWORD}"},
			"expected": 0,
		},
		"cm value with literal shell default": {
			"data": {"env": "DB_PASSWORD=${DB_PASSWORD:-synthetic}"},
			"expected": 1,
			"expected_keys": {"DB_PASSWORD"},
		},
		"cm value with nested literal shell default": {
			"data": {"env": "DB_PASSWORD=${DB_PASSWORD:-${FALLBACK_PASSWORD:-synthetic}}"},
			"expected": 1,
			"expected_keys": {"DB_PASSWORD"},
		},
		"cm value with literal placeholder default": {
			"data": {"application.properties": "db.password=${DB_PASSWORD:synthetic}"},
			"expected": 1,
			"expected_keys": {"db.password"},
		},
		"cm value with literal default without colon": {
			"data": {"env": "DB_PASSWORD=${DB_PASSWORD-synthetic}"},
			"expected": 1,
			"expected_keys": {"DB_PASSWORD"},
		},
		"cm value with literal assign default": {
			"data": {"env": "DB_PASSWORD=${DB_PASSWORD:=synthetic}"},
			"expected": 1,
			"expected_keys": {"DB_PASSWORD"},
		},
		"cm value with whitespace shell default": {
			"data": {"env": "DB_PASSWORD=${DB_PASSWORD:- }"},
			"expected": 0,
		},
		"cm value with alternative value expansion": {
			"data": {"env": "DB_PASSWORD=${DB_PASSWORD:+synthetic}"},
			"expected": 0,
		},
		"cm value with empty shell default": {
			"data": {"env": "DB_PASSWORD=${DB_PASSWORD:-}"},
			"expected": 0,
		},
		"cm value with quoted empty shell default": {
			"data": {"env": "DB_PASSWORD=${DB_PASSWORD:-\"\"}"},
			"expected": 0,
		},
		"cm value with shell default referencing another variable": {
			"data": {"env": "DB_PASSWORD=${DB_PASSWORD:-${FALLBACK_PASSWORD}}"},
			"expected": 0,
		},
		"cm value with required variable check": {
			"data": {"env": "DB_PASSWORD=${DB_PASSWORD:?DB_PASSWORD is required}"},
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
