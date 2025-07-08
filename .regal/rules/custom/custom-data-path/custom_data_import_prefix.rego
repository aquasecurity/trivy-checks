# METADATA
# description: |
#   Custom data import paths must follow the format `data.<custom_id>.*`,
#   For example, for the ID TEST-001, a valid import path would be `data.test001.<...>`.
# schemas:
# - input: schema.regal.ast
package custom.regal.rules.custom["custom-data-import-prefix"]

import rego.v1

import data.regal.ast
import data.regal.result

_allowed_prefixes := {
	"lib", # library data
	"k8s", # k8s global data
	"ds031", # for backwards compatibility
}

_pkg_annotation := [annot | some annot in input["package"].annotations; annot.scope == "package"][0]

report contains violation if {
	check_id := _pkg_annotation.custom.id
	some alias, path in ast.resolved_imports
	path[0] == "data"
	not path[1] in _allowed_prefixes
	path[1] != replace(lower(check_id), "-", "")

	violation := result.fail(rego.metadata.chain(), result.location(_pkg_annotation))
}
