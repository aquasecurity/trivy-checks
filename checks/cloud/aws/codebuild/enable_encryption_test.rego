package builtin.aws.codebuild.aws0018_test

import rego.v1

import data.builtin.aws.codebuild.aws0018 as check
import data.lib.test

test_allow_artifact_settings_with_encryption if {
	test.assert_empty(check.deny) with input as build_input({"artifactsettings": {"encryptionenabled": {"value": true}}})
}

test_allow_secondary_artifact_settings_with_encryption if {
	test.assert_empty(check.deny) with input as build_input({"secondaryartifactsettings": [{"encryptionenabled": {"value": true}}]})
}

test_disallow_artifact_settings_without_encryption if {
	test.assert_equal_message("Encryption is not enabled for project artifacts.", check.deny) with input as build_input({"artifactsettings": {"encryptionenabled": {"value": false}}})
}

test_disallow_secondary_artifact_settings_without_encryption if {
	test.assert_equal_message("Encryption is not enabled for secondary project artifacts.", check.deny) with input as build_input({"secondaryartifactsettings": [{"encryptionenabled": {"value": false}}]})
}

build_input(project) := {"aws": {"codebuild": {"projects": [project]}}}
