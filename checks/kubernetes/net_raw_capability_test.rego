package builtin.kubernetes.KSV119

import rego.v1

# Test case for a Pod with a container including NET_RAW capability
test_pod_with_container_net_raw_capability if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "net-raw-pod"},
		"spec": {"containers": [
			{
				"name": "container-a",
				"image": "nginx",
				"securityContext": {"capabilities": {"add": ["NET_RAW", "SYS_ADMIN"]}},
			},
			{
				"name": "container-b",
				"image": "busybox",
				"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}},
			},
		]},
	}

	# Assert that the result should be denied due to NET_RAW capability
	count(r) == 1
}

# Test case for a Pod with no container including NET_RAW capability
test_pod_without_container_net_raw_capability if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "no-net-raw-pod"},
		"spec": {"containers": [
			{
				"name": "container-x",
				"image": "nginx",
				"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}},
			},
			{
				"name": "container-y",
				"image": "busybox",
				"securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}},
			},
		]},
	}

	# Assert that the result should be allowed (no denial)
	count(r) == 0
}

# The finding has to point at the container that adds the capability, so that the
# report can show the offending lines.
test_net_raw_finding_points_at_the_container if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "net-raw-pod"},
		"spec": {"containers": [
			{
				"name": "container-a",
				"image": "nginx",
				"securityContext": {"capabilities": {"add": ["NET_RAW"]}},
				"__defsec_metadata": {"startline": 7, "endline": 11},
			},
			{
				"name": "container-b",
				"image": "busybox",
				"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}},
				"__defsec_metadata": {"startline": 12, "endline": 16},
			},
		]},
	}

	count(r) == 1
	r[_].msg == "container container-a of pod net-raw-pod in default namespace should not include 'NET_RAW' in securityContext.capabilities.add"
	r[_].startline == 7
}
