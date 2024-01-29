package appshield.kubernetes.KSV01011

# Test case for a RoleBinding with system_authenticated user binding
test_role_binding_with_system_authenticated_group_binding {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "RoleBinding",
		"metadata": {
			"name": "roleGroup",
			"namespace": "default",
		},
		"subjects": [
			{
				"kind": "Group",
				"name": "system:authenticated",
				"apiGroup": "rbac.authorization.k8s.io",
			},
			{
				"kind": "User",
				"name": "system:anonymous",
				"apiGroup": "rbac.authorization.k8s.io",
			},
		],
		"roleRef": {
			"kind": "Role",
			"name": "some-role",
			"apiGroup": "rbac.authorization.k8s.io",
		},
	}

	count(r) == 1
}

#Test case for a ClusterRoleBinding with system:authenticated group binding
test_cluster_role_binding_with_system_authenticate_binding {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRolebinding",
		"metadata": {
			"name": "clusterRoleGroup",
			"namespace": "default",
		},
		"subjects": [
			{
				"kind": "Group",
				"name": "system:authenticated",
				"apiGroup": "rbac.authorization.k8s.io",
			},
			{
				"kind": "User",
				"name": "system:anonymous",
				"apiGroup": "rbac.authorization.k8s.io",
			},
		],
		"roleRef": {
			"kind": "ClusterRole",
			"name": "clusterrole",
			"apiGroup": "rbac.authorization.k8s.io",
		},
	}

	count(r) == 1
}

# Test case for a RoleBinding with non system_authenticated group binding
test_role_binding_with_non_system_authenticated_binding {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "RoleBinding",
		"metadata": {
			"name": "nonRole",
			"namespace": "default",
		},
		"subjects": {
			"kind": "Group",
			"name": "system:unauthenticated",
			"apiGroup": "rbac.authorization.k8s.io",
		},
		"roleRef": {
			"kind": "Role",
			"name": "role",
			"apiGroup": "rbac.authorization.k8s.io",
		},
	}

	count(r) == 0
}

# Test case for a ClusterRoleBinding with non system_authenticated group binding
test_cluster_role_binding_with_non_system_authenticated_group_binding {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRoleBinding",
		"metadata": {
			"name": "non_anonymous_user",
			"namespace": "default",
		},
		"subjects": {
			"kind": "Group",
			"name": "system:unauthenticated",
			"apiGroup": "rbac.authorization.k8s.io",
		},
		"roleRef": {
			"kind": "ClusterRole",
			"name": "clusterrole",
			"apiGroup": "rbac.authorization.k8s.io",
		},
	}

	count(r) == 0
}
