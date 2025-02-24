package builtin.dockerfile.DS001

import rego.v1

test_allowed if {
	r := deny with input as {"Stages": [{"Name": "openjdk:8u292-oracle", "Commands": [{
		"Cmd": "from",
		"Value": ["openjdk:8u292-oracle"],
	}]}]}

	count(r) == 0
}

# Test FROM image with latest tag
test_latest_tag_denied if {
	r := deny with input as {"Stages": [{"Name": "openjdk", "Commands": [{
		"Cmd": "from",
		"Value": ["openjdk:latest"],
	}]}]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'openjdk'"
}

# Test FROM image with no tag
test_no_tag_denied if {
	r := deny with input as {"Stages": [{"Name": "openjdk", "Commands": [{
		"Cmd": "from",
		"Value": ["openjdk"],
	}]}]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'openjdk'"
}

# Test FROM with scratch
test_scratch_allowed if {
	r := deny with input as {"Stages": [{"Name": "scratch", "Commands": [{
		"Cmd": "from",
		"Value": ["scratch"],
	}]}]}

	count(r) == 0
}

test_with_variables_allowed if {
	r := deny with input as {"Stages": [
		{"Name": "alpine:3.5", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.5"],
			},
			{
				"Cmd": "arg",
				"Value": ["IMAGE=alpine:3.12"],
			},
		]},
		{"Name": "image", "Commands": [
			{
				"Cmd": "from",
				"Value": ["$IMAGE"],
			},
			{
				"Cmd": "cmd",
				"Value": [
					"python",
					"/usr/src/app/app.py",
				],
			},
		]},
	]}

	count(r) == 0
}

test_with_variables_denied if {
	r := deny with input as {"Stages": [
		{"Name": "alpine:3.5", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.5"],
			},
			{
				"Cmd": "arg",
				"Value": ["IMAGE=all-in-one"],
			},
		]},
		{"Name": "image", "Commands": [
			{
				"Cmd": "from",
				"Value": ["$IMAGE"],
			},
			{
				"Cmd": "cmd",
				"Value": [
					"python",
					"/usr/src/app/app.py",
				],
			},
		]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'all-in-one'"
}

test_multi_stage_allowed if {
	r := deny with input as {"Stages": [
		{"Name": "golang:1.15 as builder", "Commands": [
			{
				"Cmd": "from",
				"Value": ["golang:1.15", "as", "builder"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
			},
		]},
		{"Name": "alpine:3.13", "Commands": [{
			"Cmd": "from",
			"Value": ["alpine:3.13"],
		}]},
	]}

	count(r) == 0
}

test_multi_stage_base_alias_allowed if {
	r := deny with input as {"Stages": [
		{"Name": "node:14.18.1-bullseye as dependencies", "Commands": [
			{
				"Cmd": "from",
				"Value": ["node:14.18.1-bullseye", "as", "dependencies"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
			},
		]},
		{"Name": "build", "Commands": [{
			"Cmd": "from",
			"Value": ["dependencies", "as", "build"],
		}]},
	]}

	count(r) == 0
}

test_multi_stage_denied if {
	r := deny with input as {"Stages": [
		{"Name": "node:14.18.1-bullseye as dependencies", "Commands": [
			{
				"Cmd": "from",
				"Value": ["node:14.18.1-bullseye", "as", "dependencies"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
			},
		]},
		{"Name": "alpine:latest", "Commands": [{
			"Cmd": "from",
			"Value": ["alpine:latest"],
		}]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'alpine'"
}

test_multi_stage_no_tag_denied if {
	r := deny with input as {"Stages": [
		{"Name": "node:14.18.1-bullseye as dependencies", "Commands": [
			{
				"Cmd": "from",
				"Value": ["node:14.18.1-bullseye", "as", "dependencies"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
			},
		]},
		{"Name": "alpine:latest", "Commands": [{
			"Cmd": "from",
			"Value": ["alpine"],
		}]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'alpine'"
}

test_deny_latest_tag_ref_to_global_arg_with_default_value if {
	r := deny with input as {"Stages": [
		{"Name": "", "Commands": [{
			"Cmd": "arg",
			"Value": ["TAG=\"latest\""],
		}]},
		{"Name": "foo:${TAG}", "Commands": [{
			"Cmd": "from",
			"Value": ["foo:${TAG}"],
		}]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'foo'"
}

test_allow_tag_ref_to_global_arg_without_default_value if {
	r := deny with input as {"Stages": [
		{"Name": "", "Commands": [{
			"Cmd": "arg",
			"Value": ["TAG"],
		}]},
		{"Name": "foo:${TAG}", "Commands": [{
			"Cmd": "from",
			"Value": ["foo:${TAG}"],
		}]},
	]}

	count(r) == 0
}

test_allow_from_with_only_arg_without_default_value if {
	r := deny with input as {"Stages": [
		{"Name": "", "Commands": [{
			"Cmd": "arg",
			"Value": ["BASE_IMAGE"],
		}]},
		{"Name": "$BASE_IMAGE", "Commands": [{
			"Cmd": "from",
			"Value": ["$BASE_IMAGE"],
		}]},
	]}

	count(r) == 0
}

test_deny_image_ref_to_global_arg_without_default_value if {
	r := deny with input as {"Stages": [
		{"Name": "", "Commands": [{
			"Cmd": "arg",
			"Value": ["REGISTRY"],
		}]},
		{"Name": "${REGISTRY}/ubuntu", "Commands": [{
			"Cmd": "from",
			"Value": ["${REGISTRY}/ubuntu"],
		}]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image '/ubuntu'"
}

test_deny_global_arg_is_overrided_to_latest if {
	r := deny with input as {"Stages": [
		{"Name": "", "Commands": [{
			"Cmd": "arg",
			"Value": ["TAG=test"],
		}]},
		{"Name": "foo:${TAG}", "Commands": [
			{
				"Cmd": "arg",
				"Value": ["TAG=latest"],
			},
			{
				"Cmd": "from",
				"Value": ["foo:${TAG}"],
			},
		]},
		{"Name": "bar:${TAG}", "Commands": [{
			"Cmd": "from",
			"Value": ["bar:${TAG}"],
		}]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'foo'"
}

test_deny_image_ref_to_multiple_args_but_tag_latest if {
	r := deny with input as {"Stages": [
		{"Name": "", "Commands": [
			{
				"Cmd": "arg",
				"Value": ["REPO=repo"],
			},
			{
				"Cmd": "arg",
				"Value": ["IMAGE=image"],
			},
		]},
		{"Name": "$REPO/$IMAGE:latest", "Commands": [{
			"Cmd": "from",
			"Value": ["$REPO/$IMAGE:latest"],
		}]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'repo/image'"
}

test_deny_empty_tag_arg if {
	r := deny with input as {"Stages": [
		{"Name": "", "Commands": [{
			"Cmd": "arg",
			"Value": ["TAG"],
		}]},
		{"Name": "alpine$TAG", "Commands": [{
			"Cmd": "from",
			"Value": ["alpine$TAG"],
		}]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'alpine'"
}

test_deny_missing_tag_arg if {
	r := deny with input as {"Stages": [{"Name": "alpine$TAG", "Commands": [{
		"Cmd": "from",
		"Value": ["alpine$TAG"],
	}]}]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'alpine'"
}
