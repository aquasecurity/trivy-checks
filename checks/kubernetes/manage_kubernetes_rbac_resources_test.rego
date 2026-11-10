package builtin.kubernetes.KSV050

import rego.v1

test_manage_K8s_RBAC_resources_escape if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["roles"],
			"verbs": ["escalate"],
		}],
	}

	count(r) > 0
}

test_manage_K8s_RBAC_resources_bind if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["roles"],
			"verbs": ["bind"],
		}],
	}

	count(r) > 0
}

test_manage_K8s_RBAC_resources_impersonate if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["rolebindings"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) > 0
}

test_manage_K8s_RBAC_resources_all if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["rolebindings"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_manage_K8s_RBAC_resources_not_trigger_create if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["roles"],
			"verbs": ["create"],
		}],
	}

	count(r) == 0
}

test_manage_K8s_RBAC_resources_not_trigger_update if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["roles"],
			"verbs": ["update"],
		}],
	}

	count(r) == 0
}

test_manage_K8s_RBAC_resources_not_trigger_delete if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["roles"],
			"verbs": ["delete"],
		}],
	}

	count(r) == 0
}

test_manage_K8s_RBAC_resources_not_trigger_deletecollection if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["rolebindings"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) == 0
}

test_manage_K8s_RBAC_resources_not_trigger_wrong_resource if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["rolebindings1"],
			"verbs": ["*"],
		}],
	}

	count(r) == 0
}

test_manage_K8s_RBAC_resources_not_trigger_get if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["roles"],
			"verbs": ["get"],
		}],
	}

	count(r) == 0
}

test_manage_K8s_RBAC_resources_rbac_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {"name": "rbac-manager"},
		"rules": [{
			"apiGroups": ["rbac.authorization.k8s.io"],
			"resources": ["roles", "rolebindings"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_manage_K8s_RBAC_resources_not_trigger_crd_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {"name": "crossplane:provider:provider-grafana:system"},
		"rules": [{
			"apiGroups": ["enterprise.grafana.crossplane.io"],
			"resources": ["roles", "rolebindings"],
			"verbs": ["*"],
		}],
	}

	count(r) == 0
}

test_manage_K8s_RBAC_resources_not_trigger_core_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": [""],
			"resources": ["roles"],
			"verbs": ["escalate"],
		}],
	}

	count(r) == 0
}

test_manage_K8s_RBAC_resources_mixed_api_groups if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {"name": "mixed"},
		"rules": [
			{
				"apiGroups": ["transform.vault.upbound.io"],
				"resources": ["roles"],
				"verbs": ["*"],
			},
			{
				"apiGroups": ["example.com", "rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["bind"],
			},
		],
	}

	count(r) == 1
}
