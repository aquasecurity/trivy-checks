package builtin.kubernetes.KSV036

import rego.v1

test_protect_service_account_token_denied_with_automountServiceAccountToken if {
	r := deny with input as {
		"kind": "pod",
		"name": "justPOod",
		"metadata": {"name": "nginx"},
		"spec": {
			"automountServiceAccountToken": true,
			"containers": [{
				"name": "nginx",
				"image": "nginx",
				"volumeMounts": [{
					"name": "serviceaccount-vm",
					"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
				}],
			}],
		},
	}

	r[_].msg == "Container of pod 'nginx' should set 'spec.automountServiceAccountToken' to false"
}

test_protect_service_account_token_denied_without_automountServiceAccountToken if {
	r := deny with input as {
		"kind": "pod",
		"name": "justPOod",
		"metadata": {"name": "nginx"},
		"spec": {"containers": [{
			"name": "nginx",
			"image": "nginx",
			"volumeMounts": [{
				"name": "serviceaccount-vm",
				"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
			}],
		}]},
	}

	r[_].msg == "Container of pod 'nginx' should set 'spec.automountServiceAccountToken' to false"
}

test_protect_service_account_token_denied_without_mountPath if {
	r := deny with input as {
		"kind": "pod",
		"name": "justPOod",
		"metadata": {"name": "nginx"},
		"spec": {"containers": [{
			"name": "nginx",
			"image": "nginx",
			"volumeMounts": [{"name": "serviceaccount-vm"}],
		}]},
	}

	count(r) == 0
}

test_protect_service_account_token_allow if {
	r := deny with input as {
		"kind": "pod",
		"name": "jusPOod",
		"metadata": {"name": "nginx"},
		"spec": {
			"automountServiceAccountToken": false,
			"containers": [{
				"name": "nginx",
				"image": "nginx",
				"volumeMounts": [{
					"name": "serviceaccount-vm",
					"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
				}],
			}],
		},
	}

	count(r) == 0
}
