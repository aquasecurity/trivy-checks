package builtin.kubernetes.KSV0125_test

import data.builtin.kubernetes.KSV0125 as check

import rego.v1

test_check_registry[name] if {
	some name, tc in {
		"trusted registry": {
			"image": "gcr.io/test:latest",
			"expected": 0,
		},
		"untrusted registry": {
			"image": "foo.io/test:latest",
			"expected": 1,
		},
		"without registry": {
			"image": "test:latest",
			"expected": 0,
		},
	}

	inp := {
		"apiVersion": "batch/v1",
		"kind": "Job",
		"metadata": {
			"name": "test",
			"namespace": "test",
		},
		"spec": {"template": {"spec": {"containers": [{
			"name": "test",
			"image": tc.image,
		}]}}},
	}

	res := check.deny with input as inp

	count(res) == tc.expected
}

test_check_registry_custom_registries[name] if {
	some name, tc in {
		"trusted registry": {
			"image": "foo.io/test:latest",
			"expected": 0,
		},
		"untrusted registry": {
			"image": "gcr.io/test:latest",
			"expected": 1,
		},
		"without registry": {
			"image": "test:latest",
			"expected": 0,
		},
	}

	inp := {
		"apiVersion": "batch/v1",
		"kind": "Job",
		"metadata": {
			"name": "test",
			"namespace": "test",
		},
		"spec": {"template": {"spec": {"containers": [{
			"name": "test",
			"image": tc.image,
		}]}}},
	}

	res := check.deny with input as inp
		with data.ksv0125.trusted_registries as ["foo.io"]

	count(res) == tc.expected
}
