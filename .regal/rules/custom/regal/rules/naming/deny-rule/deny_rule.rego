# METADATA
# description: Ensures that no rules in the check are named with the prefix 'deny_'
# related_resources:
# - description: documentation
#   ref: https://github.com/aquasecurity/trivy-checks/pull/283
# schemas:
# - input: schema.regal.ast
package custom.regal.rules.naming["deny-rule"]

import rego.v1

import data.regal.ast
import data.regal.result

report contains violation if {
	some rule in input.rules
	startswith(ast.ref_to_string(rule.head.ref), "deny_")
	violation := result.fail(rego.metadata.chain(), result.location(rule))
}
