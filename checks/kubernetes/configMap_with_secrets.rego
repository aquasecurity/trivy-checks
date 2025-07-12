# METADATA
# title: "ConfigMap with secrets"
# description: "Storing secrets in configMaps is unsafe"
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: KSV-0109
#   aliases:
#     - AVD-KSV-0109
#     - configMap_with_secrets
#   long_id: kubernetes-configMap-with-secrets
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
	"(?i)(pw\\s*(=|:))",
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
	"(?i)(pw\\s*)",
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
# It supports splitting on '=' or ':' and ignores values that:
# - don't contain a delimiter
# - have no actual value (e.g. "PASSWORD=")
# - are interpolation references (e.g. "${VAR}", "$(command)", "{{ template }}")
config_map_secret_key(value) := key if {
	some delimiter in {":", "="}
	parts := split(value, delimiter)
	count(parts) > 1
	raw_value := parts[1]

	# skip if value is empty
	raw_value != ""

	# skip interpolated or templated values
	not is_interpolation(raw_value)

	key := parts[0]
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
