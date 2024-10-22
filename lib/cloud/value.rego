# METADATA
# custom:
#   library: true
package lib.cloud.value

import rego.v1

is_unresolvable(val) if val.unresolvable

# string

is_empty(val) := is_equal(val, "")

is_not_empty(val) := is_not_equal(val, "")

# int

less_than(val, other) := false if {
	is_unresolvable(val)
} else := val.value < other

greater_than(val, other) := false if {
	is_unresolvable(val)
} else := val.value > other

# bool

is_true(val) := is_equal(val, true)

is_false(val) := is_equal(val, false)

# common

is_equal(val, raw) := false if {
	is_unresolvable(val)
} else := val.value == raw

is_not_equal(val, raw) := false if {
	is_unresolvable(val)
} else := val.value != raw
