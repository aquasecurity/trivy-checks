package custom.regal.rules.custom["invalid-metadata_test"]

import rego.v1

import data.custom.regal.rules.custom["invalid-metadata"] as rule

test_invalid_metadata if {
	module := regal.parse_module("example.rego", `
# METADATA
# title: test title
# description: test description
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   avdid: AVD-TEST-001
#   examples: test/ff.json
package policy

foo := true`)

	r := rule.report with input as module

	r == {{
		"category": "custom",
		"description": "(Root): avd_id is required\n(Root): input is required\n(Root): Additional property avdid is not allowed",
		"level": "error",
		"location": {
			"col": 1,
			"end": {
				"col": 27,
				"row": 9,
			},
			"file": "example.rego",
			"row": 2,
			"text": "# METADATA",
		},
		"title": "invalid-metadata",
	}}
}
