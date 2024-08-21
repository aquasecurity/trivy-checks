package builtin.aws.workspaces.aws0109_test

import rego.v1

import data.builtin.aws.workspaces.aws0109 as check
import data.lib.test

test_allow_encrypted if {
	inp := {"aws": {"workspaces": {"workspaces": [{
		"rootvolume": {"encryption": {"enabled": {"value": true}}},
		"uservolume": {"encryption": {"enabled": {"value": true}}},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_root_volume_unencrypted if {
	inp := {"aws": {"workspaces": {"workspaces": [{"rootvolume": {"encryption": {"enabled": {"value": false}}}}]}}}

	test.assert_equal_message("Root volume does not have encryption enabled.", check.deny) with input as inp
}

test_deny_user_volume_unencrypted if {
	inp := {"aws": {"workspaces": {"workspaces": [{"uservolume": {"encryption": {"enabled": {"value": false}}}}]}}}

	test.assert_equal_message("User volume does not have encryption enabled.", check.deny) with input as inp
}
