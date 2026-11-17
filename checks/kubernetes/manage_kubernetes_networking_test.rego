package builtin.kubernetes.KSV056

import rego.v1

import data.lib.test

test_manage_manage_kubernetes_networking_create if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["services"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_manage_manage_kubernetes_networking_update if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["endpoints"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_manage_manage_kubernetes_networking_delete if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["endpointslices"],
			"verbs": ["delete"],
		}],
	}

	count(r) > 0
}

test_manage_manage_kubernetes_networking_deletecollection if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["networkpolicies"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_manage_manage_kubernetes_networking_impersonate if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["ingresses"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) > 0
}

test_manage_manage_kubernetes_networking_all if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["ingresses"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_manage_manage_kubernetes_networking_wrong_verb if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["ingresses"],
			"verbs": ["aa"],
		}],
	}

	count(r) == 0
}

test_manage_manage_kubernetes_networking_wrong_resource if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["services1"],
			"verbs": ["*"],
		}],
	}

	count(r) == 0
}

test_manage_kubernetes_networking_builtin_api_groups if {
	every resource, group in {
		"services": "",
		"endpoints": "",
		"endpointslices": "discovery.k8s.io",
		"networkpolicies": "networking.k8s.io",
		"ingresses": "networking.k8s.io",
	} {
		r := deny with input as {
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind": "Role",
			"metadata": {
				"namespace": "default",
				"name": "pod-reader",
			},
			"rules": [{
				"apiGroups": [group],
				"resources": [resource],
				"verbs": ["create"],
			}],
		}

		test.assert_count(r, 1)
	}
}

test_manage_kubernetes_networking_not_trigger_crd_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["example.com"],
			"resources": ["services", "endpoints", "endpointslices", "networkpolicies", "ingresses"],
			"verbs": ["create"],
		}],
	}

	test.assert_empty(r)
}
