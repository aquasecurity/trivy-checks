# METADATA
# custom:
#   library: true
package lib.cloud.metadata

import rego.v1

# Returns the object found by the given path
# if child object is not found, returns the last found object
obj_by_path(obj, path) := res if {
	occurrences := {obj_path: child_object |
		walk(obj, [obj_path, child_object])
		has_metadata(child_object)
		object.subset(path, obj_path)
	}

	res := occurrences[max(object.keys(occurrences))]
} else := obj

has_metadata(obj) if obj.__defsec_metadata

has_metadata(obj) if {
	obj.fskey
	has_key(obj, "value")
}

has_key(x, k) if _ = x[k]
