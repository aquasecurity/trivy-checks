package builtin.kubernetes.KSV024

import rego.v1

test_host_ports_defined_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-host-ports"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"ports": [{"hostPort": 8080}],
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-host-ports' should not set host ports, 'ports[*].hostPort'"
}

test_no_host_ports_defined_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-host-ports"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"ports": [{"containerPort": 80}],
		}]},
	}

	count(r) == 0
}

# Only the container that sets a host port is at fault, so it is the one the finding
# has to name and point at.
test_only_the_container_with_host_ports_is_reported if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-host-ports"},
		"spec": {"containers": [
			{
				"name": "hello",
				"image": "busybox",
				"ports": [{"hostPort": 8080}],
				"__defsec_metadata": {"startline": 7, "endline": 10},
			},
			{
				"name": "sidecar",
				"image": "busybox",
				"__defsec_metadata": {"startline": 11, "endline": 13},
			},
		]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-host-ports' should not set host ports, 'ports[*].hostPort'"
	r[_].startline == 7
}
