# METADATA
# title: "ConfigMap with secrets"
# description: "Storing secrets in configMaps is unsafe"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: KSV-0109
#   long_id: kubernetes-configMap-with-secrets
#   aliases:
#     - AVD-KSV-0109
#     - configMap_with_secrets
#     - kubernetes-configMap-with-secrets
#   severity: HIGH
#   recommended_action: "Remove password/secret from configMap data value"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: configmap
#   examples: checks/kubernetes/configMap_with_secrets.yaml
package builtin.kubernetes.KSV0109

import rego.v1

import data.lib.kubernetes

# cm_value_patterns defines regex patterns used to detect secret-like content in ConfigMap values.
# Note: adding many complex patterns may impact evaluation performance.
cm_value_patterns := {
	"(?i)(password\\s*(=|:))",
	"(?i)(pass\\s*(=|:))",
	"(?i)(pword\\s*(=|:))",
	"(?i)(passphrase\\s*(=|:))",
	"(?i)(passwrd\\s*(=|:))",
	"(?i)(passwd\\s*(=|:))",
	"(?i)(secret\\s*(=|:))",
	"(?i)(secretkey\\s*(=|:))",
	"(?i)(appSecret\\s*(=|:))",
	"(?i)(clientSecret\\s*(=|:))",
	"(?i)(aws_access_key_id\\s*(=|:))",
	"(?i)(pswrd\\s*(=|:))",
	"(?i)(token\\s*(=|:))",
	"(?i)(pwd\\s*(=|:))",
}

# cm_key_patterns defines regex patterns used to identify secret-related keys in ConfigMap data.
# Note: adding many complex patterns may impact evaluation performance.
cm_key_patterns := {
	"(?i)(password\\s*)",
	"(?i)(pass\\s*)",
	"(?i)(pword\\s*)",
	"(?i)(passphrase\\s*)",
	"(?i)(passwrd\\s*)",
	"(?i)(passwd\\s*)",
	"(?i)(secret\\s*)",
	"(?i)(secretkey\\s*)",
	"(?i)(appSecret\\s*)",
	"(?i)(clientSecret\\s*)",
	"(?i)(aws_access_key_id\\s*)",
	"(?i)(pswrd\\s*)",
	"(?i)(token\\s*)",
	"(?i)(pwd\\s*)",
}

# config_map_secrets_from_values identifies keys in ConfigMap data values that look like secret assignments.
config_map_secrets_from_values contains key if {
	kubernetes.kind == "ConfigMap"
	some k, v in kubernetes.object.data

	some pattern in cm_value_patterns
	regex.match(pattern, v)

	some line in split(v, "\n")
	regex.match(pattern, line)
	key := config_map_secret_key(line)
}

# config_map_secret_key extracts the key from a value string if it looks like a sensitive assignment.
# The line is split at the first '=' or ':', so a value may contain the other character.
# Empty values and references without a literal default are ignored.
config_map_secret_key(value) := key if {
	idx := first_assignment_index(value)
	key := substring(value, 0, idx)
	raw_value := substring(value, idx + 1, count(value))
	raw_value != ""
	not secret_value_is_reference(raw_value)
}

# first_assignment_index is the earliest '=' or ':' in the line.
first_assignment_index(value) := idx if {
	positions := [i |
		some mark in ["=", ":"]
		i := indexof(value, mark)
		i >= 0
	]
	count(positions) > 0
	idx := min(positions)
}

# secret_value_is_reference is true when the value does not embed a literal secret.
# ${VAR:-literal} and ${VAR:-${OTHER:-literal}} still contain a secret and return false.
secret_value_is_reference(val) if {
	trimmed := trim(val, "\"")
	some prefix in ["$(", "{{"]
	startswith(trimmed, prefix)
}

secret_value_is_reference(val) if {
	trimmed := trim(val, "\"")
	startswith(trimmed, "${")
	not reference_embeds_literal(trimmed)
}

# reference_embeds_literal reports shell-style defaults that are not another variable.
# Nesting is checked for the two levels described by the ConfigMap examples.
reference_embeds_literal(expr) if {
	fallback := reference_default(expr)
	default_embeds_literal(fallback)
}

reference_default(expr) := value if {
	startswith(expr, "${")
	endswith(expr, "}")
	inner := substring(expr, 2, count(expr) - 3)
	spec := regex.find_all_string_submatch_n(`^[A-Za-z_][A-Za-z0-9_]*(:-|:=|:\+|\+|:\?|-|=)([\s\S]*)$`, inner, 1)
	count(spec) == 1
	value := trim(spec[0][2], " \t")
}

default_embeds_literal(value) if {
	value != ""
	not startswith(value, "$")
}

default_embeds_literal(value) if {
	nested := reference_default(value)
	nested != ""
	not startswith(nested, "$")
}

default_embeds_literal(value) if {
	nested := reference_default(value)
	inner := reference_default(nested)
	inner != ""
	not startswith(inner, "$")
}

default_embeds_literal(value) if {
	startswith(value, "$")
	not startswith(value, "${")
	not regex.match(`^\$[A-Za-z_][A-Za-z0-9_]*$`, value)
}

# config_map_secret_keys detects ConfigMap data keys that appear to reference secrets.
# This does not inspect values — only the key names themselves.
config_map_secrets_from_keys contains key if {
	kubernetes.kind == "ConfigMap"
	some key, _ in kubernetes.object.data
	some pattern in cm_key_patterns
	regex.match(pattern, key)
}

# config_map_secrets contains all keys from ConfigMap data that match secret-related patterns.
# Used to avoid redundant evaluation of pattern matching logic (e.g. in deny rules).
config_map_secrets := config_map_secrets_from_keys | config_map_secrets_from_values

deny contains res if {
	count(config_map_secrets) > 0
	msg := kubernetes.format(sprintf(
		"%s '%s' in '%s' namespace stores secrets in key(s) or value(s) '%s'",
		[kubernetes.kind, kubernetes.name, kubernetes.namespace, config_map_secrets],
	))
	res := result.new(msg, kubernetes.kind)
}
