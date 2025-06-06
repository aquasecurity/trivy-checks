package builtin.kubernetes.KSV041

import rego.v1

test_manage_secrets if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["get"],
		}],
	}

	count(r) > 0
}

test_manage_verb_update if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_manage_verb_list if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["list"],
		}],
	}

	count(r) > 0
}

test_manage_not_secret_resource if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets1"],
			"verbs": ["list"],
		}],
	}

	count(r) == 0
}

test_manage_secret_verb_update if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_manage_secret_verb_impersonate if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) > 0
}

test_manage_secret_verb_deletecollection if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_manage_secret_verb_patch if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["patch"],
		}],
	}

	count(r) > 0
}

test_manage_secret_verb_watch if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["watch"],
		}],
	}

	count(r) > 0
}
