# METADATA
# title: "':latest' tag used"
# description: "When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# custom:
#   id: DS001
#   avd_id: AVD-DS-0001
#   severity: MEDIUM
#   short_code: use-specific-tags
#   recommended_action: "Add a tag to the image in the 'FROM' statement"
#   input:
#     selector:
#     - type: dockerfile
#   examples: checks/docker/latest_tag.yaml
package builtin.dockerfile.DS001

import rego.v1

import data.lib.docker

resolve_alias(values) := values[i + 1] if "as" == lower(values[i])

all_aliases := [resolve_alias(from.Value) | some from in docker.from]

is_alias(img) if img in all_aliases

# image_names returns the image in FROM statement.
image_names := [from.Value[0] | some from in docker.from]

# image_tags returns the image and tag.
parse_tag(name) := [img, tag] if [img, tag] = split(name, ":")

# image_tags returns the image and "latest" if a tag is not specified.
parse_tag(img) := [img, "latest"] if not contains(img, ":")

# parses the image and tag if the reference does not does not reference any variables
parse_image_and_tag(from, _) := [img, tag] if {
	reference := from.Value[0]
	not contains(reference, "$")
	[img, tag] = parse_tag(reference)
}

global_vars := stage_args(input.Stages[0])

# see https://docs.docker.com/build/building/variables/#scoping
stage_vars(stage_num) := object.union(
	global_vars,
	stage_args(input.Stages[stage_num]),
) if {
	stage_num != 0
} else := global_vars

stage_args(stage) := {name: def_value |
	some instruction in stage.Commands
	instruction.Cmd == "arg"
	[name, def_value] = parse_arg(instruction.Value[0])
}

parse_arg(raw) := [name, trim(def_value, "\"")] if {
	[name, def_value] := regex.split(`\s*=\s*`, raw)
} else := [raw, ""]

variable_pattern := `\$\{[^}]+\}|\$[a-zA-Z_][a-zA-Z0-9_]*`

find_var_refs(s) := regex.find_n(variable_pattern, s, -1)

eval_string(s, vars) := strings.replace_n(patterns, s) if {
	patterns := {var_ref: variable |
		some var_ref in find_var_refs(s)
		variable := object.get(vars, extract_var_name(var_ref), "")
	}
}

extract_var_name(s) := substring(s, 2, count(s) - 3) if startswith(s, "${")

extract_var_name(s) := substring(s, 1, count(s) - 1) if not startswith(s, "${")

# parses the image and tag if the evaluated reference does not end with a variable
# and does not contain a tag part. Example: ${REGISTRY}/foo
parse_image_and_tag(from, vars) := [img, tag] if {
	reference := from.Value[0]
	contains(reference, "$")

	res := eval_string(reference, vars)
	not contains(res, ":")
	not is_string_ending_with_var(res)

	[img, tag] = parse_tag(res)
}

# checks if the string ends with a variable.
is_string_ending_with_var(reference) if {
	some var_ref in find_var_refs(reference)
	endswith(reference, var_ref)
}

# parses the image and tag if the evaluated reference contains a tag
# that does not reference any variable. Example: ${REGISTRY}/foo:bar
parse_image_and_tag(from, vars) := [img, tag] if {
	reference := from.Value[0]
	contains(reference, "$")

	res := eval_string(reference, vars)
	[img, tag] := split(res, ":")
	not contains(tag, "$")
}

deny contains res if {
	some instruction in input.Stages[i].Commands
	instruction.Cmd == "from"

	vars := stage_vars(i)
	[img, tag] := parse_image_and_tag(instruction, vars)

	img != "scratch"
	img != ""
	not is_alias(img)
	tag == "latest"

	msg := sprintf("Specify a tag in the 'FROM' statement for image '%s'", [img])
	res := result.new(msg, instruction)
}
