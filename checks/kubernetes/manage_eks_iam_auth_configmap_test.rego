package builtin.kubernetes.KSV115

import rego.v1

import data.lib.test

test_manageEKSIAMAuthConfigmap_verb_create if {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_update if {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_patch if {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_delete if {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_deletecollection if {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_impersonate if {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_all if {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_wrong if {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) == 0
}

test_manageEKSIAMAuthConfigmap_core_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "kube-system",
			"name": "aws-auth-editor",
		},
		"rules": [{
			"apiGroups": [""],
			"resources": ["configmaps"],
			"verbs": ["update"],
			"resourceNames": ["aws-auth"],
		}],
	}

	test.assert_count(r, 1)
}

test_manageEKSIAMAuthConfigmap_not_trigger_crd_api_group if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "kube-system",
			"name": "aws-auth-editor",
		},
		"rules": [{
			"apiGroups": ["example.com"],
			"resources": ["configmaps"],
			"verbs": ["update"],
			"resourceNames": ["aws-auth"],
		}],
	}

	test.assert_empty(r)
}
