package builtin.kubernetes.KSV048

import rego.v1

test_update_malicious_pod_deployments if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["deployments"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_daemonsets if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["daemonsets"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_statefulsets if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["statefulsets"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_replicationcontrollers if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["statefulsets"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_replicasets if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["replicasets"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_cronjobs if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["cronjobs"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_not_secret_resource if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["deployments1"],
			"verbs": ["update"],
		}],
	}

	count(r) == 0
}

test_update_malicious_pod_deployment if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["deployments"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_daemonsets_2 if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["daemonsets"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_statefulsets_2 if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["statefulsets"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_replicationcontrollers_2 if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["replicationcontrollers"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_replicasets_2 if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["replicasets"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_jobs if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["jobs"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_cronjobs_2 if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["cronjobs"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_deletecollection if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["cronjobs"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_delete if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["job"],
			"verbs": ["delete"],
		}],
	}

	count(r) == 0
}

test_update_malicious_pod_patch if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["job"],
			"verbs": ["patch"],
		}],
	}

	count(r) == 0
}

test_update_malicious_pod_impersonate if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["job"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) == 0
}
