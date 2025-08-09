package builtin.kubernetes.KSV013

import rego.v1

test_image_tagging_cases[name] if {
	some name, tc in {
		"image without tag": {
			"image": "busybox",
			"expected": 1,
		},
		"image with latest tag": {
			"image": "busybox:latest",
			"expected": 1,
		},
		"image with version": {
			"image": "busybox:1.33.1",
			"expected": 0,
		},
		"image with digest only": {
			"image": "busybox@sha256:askj78jhkf278hdjkf78623gbkljmkvmk8kjn98237487hkjaf897bkjsehf783f",
			"expected": 0,
		},
		"image with latest tag and digest": {
			"image": "busybox:latest@sha256:askj78jhkf278hdjkf78623gbkljmkvmk8kjn98237487hkjaf897bkjsehf783f",
			"expected": 0,
		},
		"image with version and digest": {
			"image": "busybox:1.33.1@sha256:askj78jhkf278hdjkf78623gbkljmkvmk8kjn98237487hkjaf897bkjsehf783f",
			"expected": 0,
		},
		"registry with tag": {
			"image": "127.0.0.1:5000/busybox:1.33.1",
			"expected": 0,
		},
		"registry without tag": {
			"image": "127.0.0.1:5000/busybox",
			"expected": 1,
		},
		"registry without tag2": {
			"image": "gcr.io/google-containers/pause",
			"expected": 1,
		},
	}

	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"containers": [{
			"command": ["sh", "-c", "echo 'Hello' && sleep 1h"],
			"image": tc.image,
			"name": "hello",
		}]},
	}

	count(r) == tc.expected
}
