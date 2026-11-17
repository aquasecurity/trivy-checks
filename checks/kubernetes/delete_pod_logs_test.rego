package builtin.kubernetes.KSV042

import rego.v1

import data.lib.test

test_delete_podsLog_restricted_verb_delete if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/log"],
			"verbs": ["delete"],
		}],
	}

	count(r) > 0
}

test_delete_podsLog_restricted_verb_delete_collection if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/log"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_delete_podsLog_restricted_verb_all if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/log"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_delete_podsLog_restricted_verb_other if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/log"],
			"verbs": ["just"],
		}],
	}

	count(r) == 0
}

test_delete_podsLog_restricted_core_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": [""],
			"resources": ["pods/log"],
			"verbs": ["delete"],
		}],
	}

	test.assert_count(r, 1)
}

test_delete_podsLog_restricted_not_trigger_crd_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["example.com"],
			"resources": ["pods/log"],
			"verbs": ["delete"],
		}],
	}

	test.assert_empty(r)
}
