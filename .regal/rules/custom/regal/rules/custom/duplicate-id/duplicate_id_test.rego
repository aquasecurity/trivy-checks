package custom.regal.rules.custom["duplicate-id_test"]

import rego.v1

import data.custom.regal.rules.custom["duplicate-id"] as rule

test_fail_checks_with_duplicate_id if {
	agg1 := rule.aggregate with input as regal.parse_module("test1.rego", `
# METADATA
# custom:
#   id: TEST-001
#   avd_id: AVD-TEST-001
package test1
	`)

	agg2 := rule.aggregate with input as regal.parse_module("test2.rego", `
# METADATA
# custom:
#   id: TEST-001
#   avd_id: AVD-TEST-001
package test2
	`)

	r := rule.aggregate_report with input as {"aggregate": (agg1 | agg2)}

	r == {
		_build_result("Duplicate avd_id 'AVD-TEST-001'", "test1.rego"),
		_build_result("Duplicate avd_id 'AVD-TEST-001'", "test2.rego"),
		_build_result("Duplicate id 'TEST-001'", "test1.rego"),
		_build_result("Duplicate id 'TEST-001'", "test2.rego"),
	}
}

test_success_checks_with_unique_id if {
	agg1 := rule.aggregate with input as regal.parse_module("test1.rego", `
# METADATA
# custom:
#   id: TEST-001
#   avd_id: AVD-TEST-001
package test1
	`)

	agg2 := rule.aggregate with input as regal.parse_module("test2.rego", `
# METADATA
# custom:
#   id: TEST-002
#   avd_id: AVD-TEST-002
package test2
	`)

	r := rule.aggregate_report with input as {"aggregate": (agg1 | agg2)}

	r == set()
}

_build_result(description, file) := {
	"category": "custom",
	"description": description,
	"level": "error",
	"location": {
		"col": 1,
		"end": {
			"col": 25,
			"row": 5,
		},
		"file": file,
		"row": 2,
		"text": "# METADATA",
	},
	"title": "duplicate-id",
}
