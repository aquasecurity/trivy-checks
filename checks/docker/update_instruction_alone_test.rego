package builtin.dockerfile.DS017

test_denied {
	r := deny with input as {"Stages": [{"Name": "ubuntu:18.04", "Commands": [
		{
			"Cmd": "from",
			"Value": ["ubuntu:18.04"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install -y --no-install-recommends mysql-client && rm -rf /var/lib/apt/lists/*"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["mysql"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
}

test_json_array_denied {
	r := deny with input as {"Stages": [{"Name": "ubuntu:18.04", "Commands": [
		{
			"Cmd": "from",
			"Value": ["ubuntu:18.04"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get", "update"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["mysql"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
}

test_chained_denied {
	r := deny with input as {"Stages": [{"Name": "ubuntu:18.04", "Commands": [
		{
			"Cmd": "from",
			"Value": ["ubuntu:18.04"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && adduser mike"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install -y --no-install-recommends mysql-client && rm -rf /var/lib/apt/lists/*"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["mysql"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
}

test_multiple_package_managers {
	r := deny with input as {"Stages": [{
		"Name": "ubuntu:18.04",
		"Commands": [
			{
				"Cmd": "from",
				"Value": ["ubuntu:18.04"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update -y && apt-get upgrade -y && apt-get install -y curl && apk-update"],
			},
			{
				"Cmd": "entrypoint",
				"Value": ["mysql"],
			},
		],
	}]}

	count(r) == 0
}

test_allowed {
	r := deny with input as {"Stages": [{"Name": "ubuntu:18.04", "Commands": [
		{
			"Cmd": "from",
			"Value": ["ubuntu:18.04"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get install -y --no-install-recommends mysql-client && rm -rf /var/lib/apt/lists/*"],
		},
		{
			"Cmd": "run",
			"Value": ["apk update && apk add --no-cache git ca-certificates"],
		},
		{
			"Cmd": "run",
			"Value": ["apk --update add easy-rsa"],
		},
		{
			"Cmd": "run",
			"Value": ["/bin/sh /scripts/someScript.sh update"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install -y nginx"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["mysql"],
		},
	]}]}

	count(r) == 0
}

# TODO: improve command splitting
# test_allowed_cmds_separated_by_semicolon {
# 	r := deny with input as {"Stages": [{"Name": "ubuntu:18.04", "Commands": [
# 		{
# 			"Cmd": "from",
# 			"Value": ["ubuntu:18.04"],
# 		},
# 		{
# 			"Cmd": "run",
# 			"Value": ["apt-get update -y ; apt-get install -y curl"],
# 		},
# 		{
# 			"Cmd": "entrypoint",
# 			"Value": ["mysql"],
# 		},
# 	]}]}

# 	count(r) == 0
# }

test_allowed_multiple_install_cmds {
	r := deny with input as {"Stages": [{"Name": "ubuntu:18.04", "Commands": [
		{
			"Cmd": "from",
			"Value": ["ubuntu:18.04"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update -y && apt-get upgrade -y && apt-get install -y curl"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["mysql"],
		},
	]}]}

	count(r) == 0
}

test_allow_upgrade {
	r := deny with input as {"Stages": [{"Name": "ubuntu:18.04", "Commands": [
		{
			"Cmd": "from",
			"Value": ["ubuntu:18.04"],
		},
		{
			"Cmd": "run",
			"Value": ["test && apt-get update && apt upgrade --yes"],
		},
	]}]}

	count(r) == 0
}

test_without_install_cmd_allowed {
	r := deny with input as {"Stages": [{"Name": "alpine:latest", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:latest"],
		},
		{
			"Cmd": "run",
			"Value": ["echo \"Test\""],
		},
	]}]}

	count(r) == 0
}

test_non_package_manager_update_allowed {
	r := deny with input as {"Stages": [{"Name": "maven:alpine", "Commands": [
		{
			"Cmd": "from",
			"Value": ["FROM maven:alpine"],
		},
		{
			"Cmd": "copy",
			"Value": ["build.sbt version.sbt ./"],
		},
		{
			"Cmd": "run",
			"Value": ["sbt update "],
		},
	]}]}

	count(r) == 0
}

test_dnf_update_denied {
	r := deny with input as {"Stages": [{
		"Name": "centos:8",
		"Commands": [
			{
				"Cmd": "from",
				"Value": ["centos:8"],
			},
			{
				"Cmd": "run",
				"Value": ["dnf update -y"],
			},
		],
	}]}

	count(r) == 1
}

test_dnf_update_allowed {
	r := deny with input as {"Stages": [{
		"Name": "centos:8",
		"Commands": [
			{
				"Cmd": "from",
				"Value": ["centos:8"],
			},
			{
				"Cmd": "run",
				"Value": ["dnf update && dnf install -y dnf-plugins-core"],
			},
		],
	}]}

	count(r) == 0
}

test_zypper_update_denied {
	r := deny with input as {"Stages": [{
		"Name": "opensuse/tumbleweed",
		"Commands": [
			{
				"Cmd": "from",
				"Value": ["opensuse/tumbleweed"],
			},
			{
				"Cmd": "run",
				"Value": ["zypper up -y"],
			},
		],
	}]}

	count(r) == 1
}

test_zypper_update_allowed {
	r := deny with input as {"Stages": [{
		"Name": "opensuse/tumbleweed",
		"Commands": [
			{
				"Cmd": "from",
				"Value": ["opensuse/tumbleweed"],
			},
			{
				"Cmd": "run",
				"Value": ["zypper up -y  && zypper install -y curl wget zip unzip tar git"],
			},
		],
	}]}

	count(r) == 0
}

test_yum_update_denied {
	r := deny with input as {"Stages": [{
		"Name": "centos:latest",
		"Commands": [
			{
				"Cmd": "from",
				"Value": ["centos:latest"],
			},
			{
				"Cmd": "run",
				"Value": ["yum update -y"],
			},
		],
	}]}

	count(r) == 1
}

test_yum_update_allowed {
	r := deny with input as {"Stages": [{
		"Name": "centos:latest",
		"Commands": [
			{
				"Cmd": "from",
				"Value": ["centos:latest"],
			},
			{
				"Cmd": "run",
				"Value": ["yum update -y && yum -y install java-11-openjdk"],
			},
		],
	}]}

	count(r) == 0
}
