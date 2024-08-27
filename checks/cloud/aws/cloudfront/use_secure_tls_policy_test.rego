package builtin.aws.cloudfront.aws0013_test

import rego.v1

import data.builtin.aws.cloudfront.aws0013 as check
import data.lib.test

test_deny_distribution_using_tls_1_0 if {
	test.assert_equal_message("Distribution allows unencrypted communications", check.deny) with input as build_input({"viewercertificate": {
		"cloudfrontdefaultcertificate": {"value": false},
		"minimumprotocolversion": {"value": "TLSv1.0"},
	}})
}

test_allow_distribution_using_tls_1_2 if {
	test.assert_empty(check.deny) with input as build_input({"viewercertificate": {
		"cloudfrontdefaultcertificate": {"value": false},
		"minimumprotocolversion": {"value": check.protocol_version_tls1_2_2021},
	}})
}

test_allow_distribution_with_default_certificate_and_tls_1_0 if {
	test.assert_empty(check.deny) with input as build_input({"viewercertificate": {
		"cloudfrontdefaultcertificate": {"value": true},
		"minimumprotocolversion": {"value": "TLSv1.0"},
	}})
}

build_input(body) = {"aws": {"cloudfront": {"distributions": [body]}}}
