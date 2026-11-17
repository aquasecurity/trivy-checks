package builtin.kubernetes.KSV047

import rego.v1

import data.lib.test

test_privilege_escalation_from_node_proxy_create if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["nodes/proxy"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_privilege_escalation_from_node_proxy_get if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["nodes/proxy"],
			"verbs": ["get"],
		}],
	}

	count(r) > 0
}

test_privilege_escalation_from_node_proxy_not_secret_resource if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["nodes/proxy1"],
			"verbs": ["create"],
		}],
	}

	count(r) == 0
}

test_privilege_escalation_from_node_proxy_not_secret_resource_2 if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["nodes/proxy"],
			"verbs": ["update"],
		}],
	}

	count(r) == 0
}

test_privilege_escalation_from_node_proxy_core_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {"name": "node-proxy"},
		"rules": [{
			"apiGroups": [""],
			"resources": ["nodes/proxy"],
			"verbs": ["get"],
		}],
	}

	test.assert_count(r, 1)
}

test_privilege_escalation_from_node_proxy_not_trigger_crd_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {"name": "node-proxy"},
		"rules": [{
			"apiGroups": ["example.com"],
			"resources": ["nodes/proxy"],
			"verbs": ["get"],
		}],
	}

	test.assert_empty(r)
}
