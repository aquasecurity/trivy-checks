package builtin.kubernetes.KSV0124

import rego.v1

bad_repos := {
	"myregistry.io", # circumvented by: myregistry.io.attacker.com
	"myusername", # circumvented by: myusernameattacker
	"ubuntu", # circumvented by: ubuntu.attacker.com/evil, ubuntuevil
	"docker.io/ubuntu", # circumvented by: docker.io/ubuntuattacker/evil
}

good_repos := {
	"myregistry.azurecr.io/",
	"myusername/",
	"myimage:",
	"docker.io/library/ubuntu",
}

test_bad_repos if {
	cases := [
	{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1",
		"kind": "K8sAllowedRepos",
		"metadata": {"name": "allowedrepos"},
		"spec": {
			"match": {
				"kinds": [{
					"apiGroups": [""],
					"kinds": ["Pod"],
				}],
				"namespaces": ["default"],
			},
			"parameters": {"repos": [repo]},
		},
	} |
		some repo in bad_repos
	]
	every case in cases {
		r := deny with input as case
		count(r) > 0
	}
}

test_good_repos if {
	cases := [
	{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1",
		"kind": "K8sAllowedRepos",
		"metadata": {"name": "allowedrepos"},
		"spec": {
			"match": {
				"kinds": [{
					"apiGroups": [""],
					"kinds": ["Pod"],
				}],
				"namespaces": ["default"],
			},
			"parameters": {"repos": [repo]},
		},
	} |
		some repo in good_repos
	]

	every case in cases {
		r := deny with input as case
		count(r) == 0
	}
}
