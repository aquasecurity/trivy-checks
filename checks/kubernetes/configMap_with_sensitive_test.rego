package builtin.kubernetes.KSV01010

import rego.v1

test_configMap_with_sensitive_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ConfigMap",
		"metadata": {"name": "cm-with-sensitive"},
		"data": {
			"color.good": "blue",
			"color.bad": "yellow",
			"username": "test",
		},
	}

	count(r) == 1
	r[_].msg == "ConfigMap 'cm-with-sensitive' in 'default' namespace stores sensitive contents in key(s) or value(s) '{\"username\"}'"
}

test_configMap_with_sensitive_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ConfigMap",
		"metadata": {"name": "cm-with-sensitive"},
		"data": {
			"color.good": "blue",
			"color.bad": "yellow",
		},
	}

	count(r) == 0
}
