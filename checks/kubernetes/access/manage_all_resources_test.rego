package builtin.kubernetes.KSV046

import rego.v1

test_resource_verb_role_secrets if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["*"],
			"verbs": ["delete"],
		}],
	}

	count(r) > 0
}

test_resource_verb_role_pods if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["*"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_resource_verb_role_deployments if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["*"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_resource_verb_role_daemonsets if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["*"],
			"verbs": ["list"],
		}],
	}

	count(r) > 0
}

test_resource_verb_role_statefulsets if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["*"],
			"verbs": ["get"],
		}],
	}

	count(r) > 0
}

test_resource_verb_role_replicationcontrollers if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["*"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) > 0
}

test_resource_resource_role_no_specific_verb if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["impersonate"],
			"verbs": ["aaa"],
		}],
	}

	count(r) == 0
}

test_resource_verb_role_no_any_verb if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["*"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}
