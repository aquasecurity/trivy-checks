package builtin.kubernetes.KSV049

import rego.v1

import data.lib.test

test_manageConfigmaps_verb_create if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_update if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_patch if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["patch"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_delete if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["delete"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_deletecollection if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_impersonate if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_all if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_wrong if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["just"],
		}],
	}

	count(r) == 0
}

test_manageConfigmaps_core_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": [""],
			"resources": ["configmaps"],
			"verbs": ["create"],
		}],
	}

	test.assert_count(r, 1)
}

test_manageConfigmaps_not_trigger_crd_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["example.com"],
			"resources": ["configmaps"],
			"verbs": ["create"],
		}],
	}

	test.assert_empty(r)
}
