package builtin.aws.iam.aws0057_test

import rego.v1

import data.builtin.aws.iam.aws0057 as check
import data.lib.test

test_deny_wildcard_resource if {
    inp := build_input(false, {
        "Effect": "Allow",
        "Action": ["s3:ListBucket"],
        "Resource": ["arn:aws:s3:::*"],
        "Principal": {"AWS": ["arn:aws:iam::1234567890:root"]}
    })

    test.assert_equal_message(`IAM policy document uses sensitive action "" on wildcarded resource "arn:aws:s3:::*"`, check.deny) with input as inp
}

test_allow_builtin_policy_with_wildcard_resource if {
    inp := build_input(true, {
        "Effect": "Allow",
        "Action": ["s3:ListBucket"],
        "Resource": ["arn:aws:s3:::*"],
        "Principal": {"AWS": ["arn:aws:iam::1234567890:root"]}
    })
}

test_deny_wildcard_action if {
    inp := build_input(false, {
        "Effect": "Allow",
        "Action": ["s3:*"],
        "Resource": ["arn:aws:s3:::bucket-name"],
        "Principal": {"AWS": ["arn:aws:iam::1234567890:root"]}
    })
    test.assert_equal_message(`IAM policy document uses wildcarded action "s3:*"`, check.deny) with input as inp
}

test_allow_policy_without_wildcards if {
    inp := build_input(false, {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": ["arn:aws:s3:::bucket-name"],
        "Principal": {"AWS": ["arn:aws:iam::1234567890:root"]}
    })
}

test_allow_wildcard_resource_for_cloudwatch_log_group if {
    inp := build_input(false, {
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream"],
        "Resource": ["arn:aws:logs:us-west-2:123456789012:log-group:SampleLogGroupName:*"]
    })
    test.assert_empty(check.deny) with input as inp
}

test_deny_wildcard_resource_for_cloudwatch_log_stream if {
    inp := build_input(false, {
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream"],
        "Resource": ["*"]
    })

    test.assert_equal_message("IAM policy document uses sensitive action \"logs:CreateLogStream\" on wildcarded resource \"arn:aws:logs:us-west-2:123456789012:log-group:SampleLogGroupName:*\"", check.deny) with input as inp
}


## TODO: add tests for multiply policies/resources


build_input(builtin, statement) := {
    "aws": {
        "iam": {
            "policies": [{
                "builtin": { "value": builtin },
                "document": {
                    "value": json.marshal({"Statement": [statement]})
                }
            }]
        }
    }
}