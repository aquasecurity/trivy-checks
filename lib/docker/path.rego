# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: dockerfile
package lib.path

import rego.v1

is_sub_path(a, b) if startswith(clean_path(a), clean_path(b))

clean_path(p) := remove_trailing_slash(remove_leading_slash(remove_leading_dot(unquote(p))))

unquote(s) := cut_prefix(cut_suffix(s, "\""), "\"")

remove_leading_dot(p) := cut_prefix(p, ".")

remove_leading_slash(p) := cut_prefix(p, "/")

remove_trailing_slash(p) := cut_suffix(p, "/")

cut_prefix(s, prefix) := substring(s, 1, -1) if {
	startswith(s, prefix)
} else := s

cut_suffix(s, suffix) := substring(s, 0, count(s) - 1) if {
	endswith(s, suffix)
} else := s
