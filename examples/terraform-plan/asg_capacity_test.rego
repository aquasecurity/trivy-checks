package user.terraform.asg_capacity_check_test

import rego.v1

import data.user.terraform.asg_capacity_check as check

test_deny_asg_too_much_capacity if {
	res := check.deny with input as {
		"format_version": "0.1",
		"terraform_version": "0.12.6",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_autoscaling_group.this",
			"mode": "managed",
			"type": "aws_autoscaling_group",
			"name": "this",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {"desired_capacity": 20},
		}]}},
	}

	count(res) == 1
}

test_allow_asg_ok_capacity if {
	res := check.deny with input as {
		"format_version": "0.1",
		"terraform_version": "0.12.6",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_autoscaling_group.this",
			"mode": "managed",
			"type": "aws_autoscaling_group",
			"name": "this",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {"desired_capacity": 5},
		}]}},
	}

	res == set()
}
