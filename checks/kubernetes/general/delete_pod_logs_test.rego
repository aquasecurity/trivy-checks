package builtin.kubernetes.KSV042

import rego.v1

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
