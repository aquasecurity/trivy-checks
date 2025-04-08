# METADATA
# description: Duplicate check ID
# schemas:
# - input: schema.regal.ast
package custom.regal.rules.custom["duplicate-id"]

import rego.v1

import data.regal.ast
import data.regal.result

_pkg_annotations := [annot | some annot in input["package"].annotations; annot.scope == "package"]

aggregate contains entry if {
	some annot in _pkg_annotations
	entry := result.aggregate(rego.metadata.chain(), {
		"id": annot.custom.id,
		"avd_id": annot.custom.avd_id,
		"location": result.location(annot),
	})
}

_fields_to_check := ["id", "avd_id"]

# METADATA
# schemas:
#   - input: schema.regal.aggregate
aggregate_report contains violation if {
	some field in _fields_to_check

	groups := {avd_id: locations |
		some entry in input.aggregate
		avd_id := entry.aggregate_data[field]
		locations := [loc |
			some e in input.aggregate
			e.aggregate_data[field] == avd_id
			loc := e.aggregate_data.location
		]
	}

	some avd_id, locations in groups
	count(locations) > 1

	some location in locations
	violation := result.fail(rego.metadata.chain(), object.union(
		location,
		{"description": sprintf("Duplicate %s '%s'", [field, avd_id])},
	))
}
