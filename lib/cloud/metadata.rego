# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.cloud.metadata

import rego.v1

# Returns the object found by the given path
# if child object is not found, returns the last found object
obj_by_path(obj, path) := res if {
	occurrences := {obj_path: child_object |
		walk(obj, [obj_path, child_object])
		child_object.__defsec_metadata
		object.subset(path, obj_path)
	}

	res := occurrences[max(object.keys(occurrences))]
} else := obj
