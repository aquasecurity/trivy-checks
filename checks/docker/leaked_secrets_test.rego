package builtin.dockerfile.DS031_test

import rego.v1

import data.builtin.dockerfile.DS031 as check

test_deny_secret_env_variable if {
	res := check.deny with input as build_simple_input("env", ["GITHUB_TOKEN", "placeholder", "="])
	count(res) = 1
}

test_deny_secret_arg_variable_with_default if {
	res := check.deny with input as build_simple_input("arg", ["GITHUB_TOKEN=placeholder"])
	count(res) = 1
}

test_deny_secret_arg if {
	res := check.deny with input as build_simple_input("arg", ["GITHUB_TOKEN"])
	count(res) = 1
}

test_deny_custom_secret_env if {
	inp := build_simple_input("env", ["MY_SECRET", "test", "="])
	res := check.deny with input as inp with data.ds031.included_envs as ["MY_SECRET"]
	count(res) = 1
}

test_deny_secret_arg_with_prefix if {
	inp := build_simple_input("arg", ["VITE_AWS_ACCESS_KEY_ID=REPLACE_WITH_YOUR_OWN"])
	res := check.deny with input as inp
	count(res) = 1
}

test_deny_multiply_args_in_same_line if {
	inp := build_simple_input("arg", ["FOO=test", "GITHUB_TOKEN"])
	res := check.deny with input as inp
	count(res) = 1
}

test_deny_env_legacy_format if {
	inp := build_simple_input("env", ["GITHUB_TOKEN", "test", ""])
	res := check.deny with input as inp
	count(res) = 1
}

test_deny_multiply_envs_in_same_line if {
	inp := build_simple_input("env", ["FOO", "test", "=", "GITHUB_TOKEN", "test", "="])
	res := check.deny with input as inp
	count(res) = 1
}

test_deny_copy_secret_file if {
	inp := build_input([instruction("copy", ["./config", "$AWS_CONFIG_FILE"])])
	res := check.deny with input as inp
	count(res) = 1
}

test_allow_secret_file_without_copy if {
	inp := build_simple_input("env", ["GOOGLE_APPLICATION_CREDENTIALS", "/credentials/google-storage-service.json", "="])
	res := check.deny with input as inp
	count(res) = 0
}

test_allow_secret_file_copy_with_other_base_path if {
	inp := build_input([
		instruction("copy", ["/src", "/src"]),
		instruction("env", ["GOOGLE_APPLICATION_CREDENTIALS", "=", "./app/google-storage-service.json"]),
	])
	res := check.deny with input as inp
	count(res) = 0
}

test_deny_secret_file if {
	inp := build_input([
		instruction("copy", ["/src", "/app/"]),
		instruction("env", ["GOOGLE_APPLICATION_CREDENTIALS", "./app/google-storage-service.json", "="]),
	])
	res := check.deny with input as inp
	count(res) = 1
}

test_deny_secret_file_quoted_path if {
	inp := build_input([
		instruction("copy", [".", "."]),
		instruction("env", ["GOOGLE_APPLICATION_CREDENTIALS", "\"./news-extraction.json\"", "="]),
	])
	res := check.deny with input as inp
	count(res) = 1
}

test_deny_secret_file_in_arg if {
	inp := build_input([
		instruction("copy", ["/src", "/app/"]),
		instruction("arg", ["GOOGLE_APPLICATION_CREDENTIALS=./app/google-storage-service.json"]),
	])
	res := check.deny with input as inp
	count(res) = 1
}

test_deny_secret_in_set_command if {
	inp := {"Stages": [{
		"Name": "ubuntu:22.04",
		"Commands": [instruction(
			"run",
			[`if [[-z "$GOOGLE_APPLICATION_CREDENTIALS"]]; then gcloud auth activate-service-account --key-file=${GOOGLE_APPLICATION_CREDENTIALS}; fi`],
		)],
	}]}

	res := check.deny with input as inp
	count(res) = 1
}

test_allow_secret_in_set_command_with_secret_mount if {
	inp := {"Stages": [{
		"Name": "amazon/aws-cli:latest",
		"Commands": [{
			"Cmd": "run",
			"Value": ["aws configure set aws_access_key_id $(cat /run/secrets/aws-key-id) &&     aws configure set aws_secret_access_key $(cat /run/secrets/aws-secret-key)"],
			"Flags": [
				"--mount=type=secret,id=aws-key-id,env=AWS_ACCESS_KEY_ID",
				"--mount=type=secret,id=aws-secret-key,env=AWS_SECRET_ACCESS_KEY",
			],
		}],
	}]}

	res := check.deny with input as inp
	count(res) = 0
}

test_deny_secret_key if {
	# starts with uppercase secret token
	case1 := check.deny with input as build_simple_input("env", ["SECRET_PASSPHRASE", "test", "="])
	count(case1) = 1

	# starts with lowercase secret token
	case2 := check.deny with input as build_simple_input("env", ["password", "test", "="])
	count(case2) = 1

	# contains uppercase secret token after underscore
	case3 := check.deny with input as build_simple_input("arg", ["AWS_SECRET_ACCESS_KEY"])
	count(case3) = 1

	case4 := check.deny with input as build_simple_input("arg", ["ARTIFACTORY_USR"])
	count(case4) = 1

	case5 := check.deny with input as build_simple_input("arg", ["ARTIFACTORY_PSW"])
	count(case5) = 1
}

test_allow_secret_key if {
	# starts with uppercase secret token
	case1 := check.deny with input as build_simple_input("env", ["PUBLIC_KEY", "test", "="])
	count(case1) = 0

	# starts with lowercase secret token
	case2 := check.deny with input as build_simple_input("arg", ["public_token"])
	count(case2) = 0
}

instruction(cmd, val) := {
	"Cmd": cmd,
	"Value": val,
}

build_simple_input(cmd, val) := build_input([instruction(cmd, val)])

build_input(cmds) := {"Stages": [{"Name": "busybox", "Commands": cmds}]}
