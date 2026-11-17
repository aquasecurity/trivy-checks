package builtin.kubernetes.KSV120

import rego.v1

test_cap_without_sys_admin_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sys-admin-capabilities"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_cap_add_sys_admin_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sys-admin-capabilities"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"add": ["SYS_MODULE"]}},
		}]},
	}

	count(r) == 1
}

# Each offending container is reported once, named, and not as a dump of the whole
# container object.
test_sys_module_reports_each_container_once if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "sys-module-pod"},
		"spec": {"containers": [
			{
				"name": "container-a",
				"image": "nginx",
				"securityContext": {"capabilities": {"add": ["SYS_MODULE"]}},
				"__defsec_metadata": {"startline": 7, "endline": 11},
			},
			{
				"name": "container-b",
				"image": "busybox",
				"securityContext": {"capabilities": {"add": ["SYS_MODULE"]}},
				"__defsec_metadata": {"startline": 12, "endline": 16},
			},
		]},
	}

	count(r) == 2
	{res.msg | some res in r} == {
		"container container-a of pod sys-module-pod in default namespace should not include 'SYS_MODULE' in securityContext.capabilities.add",
		"container container-b of pod sys-module-pod in default namespace should not include 'SYS_MODULE' in securityContext.capabilities.add",
	}
	{res.startline | some res in r} == {7, 12}
}
