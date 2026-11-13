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
	assigns_literal(line, pattern)
	key := assignment_key(line)
}

# assigns_literal is true if the first match of pattern in line is followed by a literal value.
# The value is taken after the match rather than after the first delimiter, so a secret in
# "url: ${HOST}/x?password=synthetic" is still found.
assigns_literal(line, pattern) if {
	match := regex.find_all_string_submatch_n(concat("", [pattern, "(.*)"]), line, 1)[0]
	is_literal_value(trim_space(match[count(match) - 1]))
}

# assignment_key returns the part of an assignment line before the first '=' or ':'.
assignment_key(line) := trim_space(parts[1]) if {
	parts := regex.find_all_string_submatch_n(`^([^:=]+)[:=]`, line, 1)[0]
}

# is_literal_value is true for a non-empty value that is not an interpolation (e.g. "${VAR}",
# "$(command)", "{{ template }}"), and for a reference with a non-empty literal default
# (e.g. "${VAR:-default}", "${VAR:-${OTHER:-default}}", "${VAR:default}").
is_literal_value(value) if {
	value != ""
	not is_interpolation(value)
}

is_literal_value(value) if {
	default_value := reference_default(value)
	default_value != ""

	# skip references to other variables and the ':+' and ':?' expansions
	not regex.match(`^[-+?=$]`, default_value)
}

# reference_default returns the innermost default of a "${VAR...}" reference.
# "${VAR:offset}" is also treated as a default because it cannot be told apart from "${VAR:default}".
reference_default(value) := trim(match[1], "\"' ") if {
	match := regex.find_all_string_submatch_n(
		`^"?(?:\$\{[A-Za-z_][A-Za-z0-9_]*(?::?[-=]|:))+([^}]*)\}`,
		value, 1,
	)[0]
}

# is_interpolation returns true if the string starts with any known interpolation prefix
is_interpolation(val) if {
	trimmed := trim_prefix(val, "\"")
	some prefix in {"${", "$(", "{{"}
	startswith(trimmed, prefix)
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
