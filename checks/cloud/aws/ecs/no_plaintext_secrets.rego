# METADATA
# title: Task definition defines sensitive environment variable(s).
# description: |
#   You should not make secrets available to a user in plaintext in any scenario. Secrets can instead be pulled from a secure secret storage system by the service requiring them.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html
#   - https://www.vaultproject.io/
# custom:
#   id: AVD-AWS-0036
#   avd_id: AVD-AWS-0036
#   provider: aws
#   service: ecs
#   severity: CRITICAL
#   short_code: no-plaintext-secrets
#   recommended_action: Use secrets for the task definition
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ecs
#             provider: aws
#   examples: checks/cloud/aws/ecs/no_plaintext_secrets.yaml
package builtin.aws.ecs.aws0036

import rego.v1

deny contains res if {
	some container in input.aws.ecs.taskdefinitions[_].containerdefinitions
	some env in container.environment
	scan_result := scan_env_value(env)
	scan_result.transgressionFound
	res := result.new(
		sprintf("Container definition contains a potentially sensitive in environment variable %q: %s", [env.name, scan_result.description]),
		container,
	)
}

scan_env_value(env) := squealer.scan_string(get_value(env.value))

deny contains res if {
	some container in input.aws.ecs.taskdefinitions[_].containerdefinitions
	some env in container.environment
	is_sensitive_attr(get_value(env.name))
	res := result.new(
		sprintf("Container definition contains a potentially sensitive in environment variable name %q", [env.name]),
		container,
	)
}

get_value(attr) := attr if {
	is_string(attr)
} else := attr.value if {
	not is_string(attr)
}

is_sensitive_attr(attr) if {
	attrl := lower(attr)
	attrl in sensitive_attribute_tokens
}

is_sensitive_attr(attr) if {
	attrl := lower(attr)
	not attrl in sensitive_attribute_tokens
	some token in sensitive_attribute_tokens
	contains(attrl, token)
	not is_whitelisted(attrl)
}

is_whitelisted(attr) if {
	some token in whitelist_tokens
	startswith(attr, token)
}

sensitive_attribute_tokens := {
	"password",
	"secret",
	"private_key",
	"aws_access_key_id",
	"aws_secret_access_key",
	"token",
	"api_key",
}

whitelist_tokens := {
	"token_type",
	"version",
}
