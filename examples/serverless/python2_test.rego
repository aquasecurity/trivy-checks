package user.serverless.avoid_python2_test

import rego.v1

import data.user.serverless.avoid_python2 as check

test_deny_python2_runtime if {
	inp := {
		"service": "aws-python-alexa-skill",
		"frameworkVersion": ">=1.4.0 <2.0.0",
		"provider": {
			"name": "aws",
			"runtime": "python2.7",
		},
		"functions": {"luckyNumber": {
			"handler": "handler.lucky_number",
			"events": ["alexaSkill"],
		}},
	}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_python3_runtime if {
	inp := {
		"service": "aws-python",
		"frameworkVersion": "4",
		"provider": {
			"name": "aws",
			"runtime": "python3.12",
		},
		"functions": {"hello": {"handler": "handler.hello"}},
	}

	res := check.deny with input as inp
	res == set()
}
