package builtin.aws.sqs.aws0096_test

import rego.v1

import data.builtin.aws.sqs.aws0096 as check
import data.lib.test

test_allow_encrypted if {
	inp := {"aws": {"sqs": {"queues": [{
		"__defsec_metadata": {"managed": true},
		"encryption": {
			"kmskeyid": {"value": "alias/key"},
			"managedencryption": {"value": true},
		},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_without_key_but_managed if {
	inp := {"aws": {"sqs": {"queues": [{
		"__defsec_metadata": {"managed": true},
		"encryption": {
			"kmskeyid": {"value": ""},
			"managedencryption": {"value": true},
		},
	}]}}}
}

test_deny_unencrypted if {
	inp := {"aws": {"sqs": {"queues": [{
		"__defsec_metadata": {"managed": true},
		"encryption": {
			"kmskeyid": {"value": ""},
			"managedencryption": {"value": false},
		},
	}]}}}

	test.assert_equal_message("Queue is not encrypted", check.deny) with input as inp
}
