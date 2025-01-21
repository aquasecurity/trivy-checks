# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: dockerfile
package lib.cmdutil

import rego.v1

is_tool(tokens, tool) if tokens[0] == tool

is_command(tokens, command) if {
	no_flags := [t | some t in tokens; not startswith(t, "-")]
	no_flags[1] == command
}

has_flag(tokens, flag) if {
	some token in tokens
	flag == token
}

to_command_string(value) := concat(" ", value)
