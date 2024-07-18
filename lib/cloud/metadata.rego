# METADATA
# custom:
#   library: true
package lib.cloud.metadata

import rego.v1

# Returns the object found by the given path
# if child object is not found, returns the last found object
obj_by_path(obj, path) := res if {
	occurrenses := {obj_path: child_object |
		walk(obj, [obj_path, child_object])
		child_object.__defsec_metadata
		object.subset(path, obj_path)
	}

	res := occurrenses[max(object.keys(occurrenses))]
} else := obj
