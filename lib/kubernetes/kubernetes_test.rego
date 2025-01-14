package lib.kubernetes

import rego.v1

test_pod if {
	# spec
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-pod",
		}]},
	}

	test_pods[_].spec.containers[_].name == "hello-pod"
}

test_cron_job if {
	# spec -> jobTemplate -> spec -> template -> spec
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "CronJob",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {
			"restartPolicy": "OnFailure",
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello !' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello-cron-job",
			}],
		}}}}},
	}

	test_pods[_].spec.containers[_].name == "hello-cron-job"
}

test_deployment if {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "Deployment",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-deployment",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-deployment"
}

test_deploymentconfig if {
	# spec -> template
	mock = {
		"apiVersion": "apps.openshift.io/v1",
		"kind": "DeploymentConfig",
		"metadata": {"name": "hello"},
		"spec": {"template": {"spec": {
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello !' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello-deploymentconfig-1",
			}],
			"volumes": [
				{
					"name": "hello-volume-1",
					"emptyDir": {},
				},
				{
					"name": "hello-volume-2",
					"emptyDir": {},
				},
			],
		}}},
	}

	test_containers := containers with input as mock
	test_volumes := volumes with input as mock

	test_containers[_].name == "hello-deploymentconfig-1"
	test_volumes[_].name == "hello-volume-2"
}

test_stateful_set if {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "StatefulSet",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-stateful-set",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-stateful-set"
}

test_daemon_set if {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "DaemonSet",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-daemon-set",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-daemon-set"
}

test_replica_set if {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "ReplicaSet",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-replica-set",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-replica-set"
}

test_replication_controller if {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "ReplicationController",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-replication-controller",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-replication-controller"
}

test_job if {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "Job",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-job",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-job"
}

test_init_containers if {
	test_containers := containers with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"spec": {"initContainers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-init-containers",
		}]},
	}

	test_containers[_].name == "hello-init-containers"
}

test_containers if {
	test_containers := containers with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"spec": {
			"securityContext": {
				"runAsUser": 1000,
				"runAsGroup": 1001,
				"fsGroup": 2000,
				"supplementalGroups": [4000],
			},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello !' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello-containers",
				"securityContext": {
					"runAsGroup": 3000,
					"allowPrivilegeEscalation": false,
				},
			}],
		},
	}

	test_containers[_].name == "hello-containers"
	test_containers[_].securityContext == {
		"runAsUser": 1000,
		"runAsGroup": 3000,
		"allowPrivilegeEscalation": false,
	}
}

test_isapiserver_has_valid_container if {
	apiserver_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-apiserver",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": ["kube-apiserver-invalid"],
				"name": "invalid-1",
			},
			{
				"command": [
					"/usr/bin/kube-apiserver",
					"--test-flag=test",
				],
				"name": "valid-1",
			},
			{
				"command": ["invalid-kube-apiserver"],
				"name": "invalid-2",
			},
			{
				"command": [
					"kube-apiserver",
					"--test-flag=test",
				],
				"name": "valid-2",
			},
		]},
	}

	is_apiserver(apiserver_container)
	apiserver_container.name in {"valid-1", "valid-2"}
}

test_isapiserver_has_not_valid_container if {
	apiserver_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-apiserver",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": [
					"/usr/bin-kube-apiserver",
					"--test-flag=test",
				],
				"name": "invalid-1",
			},
			{
				"command": ["kube-apiserver-invalid"],
				"name": "invalid-2",
			},
			{
				"command": ["kube-apiserver-invalid"],
				"name": "invalid-3",
			},
		]},
	}
	not is_apiserver(apiserver_container)
}

test_etcd_has_valid_container if {
	etcd_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": ["etcd-invalid"],
				"name": "invalid-1",
			},
			{
				"command": [
					"/usr/bin/etcd",
					"--test-flag=test",
				],
				"name": "valid-1",
			},
			{
				"command": ["invalid-etcd"],
				"name": "invalid-2",
			},
			{
				"command": [
					"etcd",
					"--test-flag=test",
				],
				"name": "valid-2",
			},
		]},
	}
	is_etcd(etcd_container)
	etcd_container.name in {"valid-1", "valid-2"}
}

test_etcd_has_not_valid_container if {
	etcd_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": [
					"/usr/bin-etcd",
					"--test-flag=test",
				],
				"name": "invalid-1",
			},
			{
				"command": ["etcd-invalid"],
				"name": "invalid-2",
			},
			{
				"command": ["etcd-invalid"],
				"name": "invalid-3",
			},
		]},
	}
	not is_etcd(etcd_container)
}

test_controllermananager_has_valid_container if {
	controllermananager_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-controller-manager",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": ["kube-controller-manager-invalid"],
				"name": "invalid-1",
			},
			{
				"command": [
					"/usr/bin/kube-controller-manager",
					"--test-flag=test",
				],
				"name": "valid-1",
			},
			{
				"command": ["invalid-kube-controller-manager"],
				"name": "invalid-2",
			},
			{
				"command": [
					"kube-controller-manager",
					"--test-flag=test",
				],
				"name": "valid-2",
			},
		]},
	}
	is_controllermanager(controllermananager_container)
	controllermananager_container.name in {"valid-1", "valid-2"}
}

test_controllermananager_has_not_valid_container if {
	controllermananager_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-controller-manager",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": [
					"/usr/bin-kube-controller-manager",
					"--test-flag=test",
				],
				"name": "invalid-1",
			},
			{
				"command": ["kube-controller-manager-invalid"],
				"name": "invalid-2",
			},
			{
				"command": ["kube-controller-manager-invalid"],
				"name": "invalid-3",
			},
		]},
	}
	not is_controllermanager(controllermananager_container)
}

test_scheduler_has_valid_container if {
	scheduler_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-scheduler",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": ["kube-scheduler-invalid"],
				"name": "invalid-1",
			},
			{
				"command": [
					"/usr/bin/kube-scheduler",
					"--test-flag=test",
				],
				"name": "valid-1",
			},
			{
				"command": ["invalid-kube-scheduler"],
				"name": "invalid-2",
			},
			{
				"command": [
					"kube-scheduler",
					"--test-flag=test",
				],
				"name": "valid-2",
			},
		]},
	}
	is_scheduler(scheduler_container)
	scheduler_container.name in {"valid-1", "valid-2"}
}

test_scheduler_has_not_valid_container if {
	scheduler_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-scheduler",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": [
					"/usr/bin-kube-scheduler",
					"--test-flag=test",
				],
				"name": "invalid-1",
			},
			{
				"command": ["kube-scheduler-invalid"],
				"name": "invalid-2",
			},
			{
				"command": ["kube-scheduler-invalid"],
				"name": "invalid-3",
			},
		]},
	}
	not is_scheduler(scheduler_container)
}
