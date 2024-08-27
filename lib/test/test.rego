# METADATA
# custom:
#   library: true
package lib.test

import rego.v1

assert_empty(v) if {
	not _assert_not_empty(v)
}

_assert_not_empty(v) if {
	count(v) > 0
	trace_and_print(sprintf("assert_not_empty:\n %v", [v]))
}

assert_equal_message(expected, results) if {
	assert_count(results, 1)
	not _assert_not_equal_message(results, expected)
}

_assert_not_equal_message(expected, results) if {
	msg := [res.msg | some res in results][0]
	msg != expected
	trace_and_print(sprintf("assert_equal_message:\n Got %q\n Expected %q", [msg, expected]))
}

assert_count(results, expected) if {
	not _assert_not_count(results, expected)
}

_assert_not_count(results, expected) if {
	count(results) != expected
	trace_and_print(sprintf("assert_count:\n Got %v\n Expected %v", [count(results), expected]))
}

trace_and_print(v) if {
	trace(v)
	print(v)
}
