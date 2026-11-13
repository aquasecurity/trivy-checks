package builtin.kubernetes.KSV004_test

import rego.v1

import data.builtin.kubernetes.KSV004 as check
import data.lib.test

test_deny_no_capabilities_dropped if {
	inp := {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-drop-capabilities"},
		"spec": {"containers": [{
			"image": "busybox",
			"name": "hello",
		}]},
	}

	test.assert_equal_message("Container 'hello' of 'pod' 'hello-drop-capabilities' in 'default' namespace should set securityContext.capabilities.drop", check.deny) with input as inp
}

test_deny_capabilities_added_but_none_dropped if {
	inp := {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-drop-capabilities"},
		"spec": {"containers": [{
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}},
		}]},
	}

	test.assert_equal_message("Container 'hello' of 'pod' 'hello-drop-capabilities' in 'default' namespace should set securityContext.capabilities.drop", check.deny) with input as inp
}

test_allow_capability_dropped if {
	inp := {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-drop-capabilities"},
		"spec": {"containers": [{
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"drop": ["NET_RAW"]}},
		}]},
	}

	test.assert_empty(check.deny) with input as inp
}

test_deny_only_the_container_without_drop if {
	inp := {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "hello-drop-capabilities",
			"namespace": "custom-namespace",
		},
		"spec": {"containers": [
			{
				"image": "busybox",
				"name": "compliant",
				"securityContext": {"capabilities": {"drop": ["NET_RAW"]}},
			},
			{
				"image": "busybox",
				"name": "non-compliant",
			},
		]},
	}

	test.assert_equal_message("Container 'non-compliant' of 'pod' 'hello-drop-capabilities' in 'custom-namespace' namespace should set securityContext.capabilities.drop", check.deny) with input as inp
}
