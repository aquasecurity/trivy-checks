package user.cf.ensure_required_tags_test

import rego.v1

import data.user.cf.ensure_required_tags as check

test_deny_resources_without_tags if {
	inp := {
		"AWSTemplateFormatVersion": "2010-09-09",
		"Resources": {"MyEC2Instance": {
			"Type": "AWS::EC2::Instance",
			"Properties": {
				"InstanceType": "t2.micro",
				"ImageId": "ami-0abcdef1234567890",
			},
		}},
	}

	res := check.deny with input as inp with data.required_tags as {
		"Environment",
		"Owner",
	}

	count(res) == 1
}

test_deny_resources_without_required_tags if {
	inp := {
		"AWSTemplateFormatVersion": "2010-09-09",
		"Resources": {"MyEC2Instance": {
			"Type": "AWS::EC2::Instance",
			"Properties": {
				"InstanceType": "t2.micro",
				"ImageId": "ami-0abcdef1234567890",
			},
			"Tags": [
				{
					"Key": "Foo",
					"Value": "foo",
				},
				{
					"Key": "Bar",
					"Value": "bar",
				},
			],
		}},
	}

	res := check.deny with input as inp with data.required_tags as {
		"Environment",
		"Owner",
	}
	count(res) == 2
}

test_allow_resources_with_required_tags if {
	inp := {
		"AWSTemplateFormatVersion": "2010-09-09",
		"Resources": {"MyEC2Instance": {
			"Type": "AWS::EC2::Instance",
			"Properties": {
				"InstanceType": "t2.micro",
				"ImageId": "ami-0abcdef1234567890",
			},
			"Tags": [
				{
					"Key": "Environment",
					"Value": "Production",
				},
				{
					"Key": "Owner",
					"Value": "JohnDoe",
				},
			],
		}},
	}

	res := check.deny with input as inp
	res == set()
}
