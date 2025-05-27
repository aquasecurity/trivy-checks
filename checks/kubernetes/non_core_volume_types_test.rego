package builtin.kubernetes.KSV028

import rego.v1

test_disallowed_volume_type_used_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-volume-types"},
		"spec": {
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
			"volumes": [{
				"name": "volume-a",
				"scaleIO": {
					"gateway": "https://localhost:443/api",
					"system": "scaleio",
					"protectionDomain": "sd0",
					"storagePool": "sp1",
					"volumeName": "vol-a",
					"secretRef": {"name": "sio-secret"},
					"fsType": "xfs",
				},
			}],
		},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-volume-types' should set 'spec.volumes[*]' to an allowed volume type"
}

test_no_volume_type_used_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-volume-types"},
		"spec": {
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
			"volumes": [{"name": "volume-a"}],
		},
	}

	count(r) == 0
}
