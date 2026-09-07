# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.aws.apigateway

import rego.v1

import data.lib.cloud.value

# Glob patterns covering all secure API Gateway security policies.
# Using patterns rather than an exact list means newly-released policies
# in the same families (TLS12_*_EDGE, TLS13_*) are automatically accepted
# without a change here.
#
# The complete set of currently-defined values is:
#   TLS_1_0                               — insecure (only TLS 1.0)
#   TLS_1_2                               — secure (legacy name, TLS 1.2+)
#   SecurityPolicy_TLS12_2018_EDGE        — secure
#   SecurityPolicy_TLS12_PFS_2025_EDGE    — secure
#   SecurityPolicy_TLS13_2025_EDGE        — secure
#   SecurityPolicy_TLS13_1_2_2021_06      — secure
#   SecurityPolicy_TLS13_1_2_PQ_2025_09   — secure
#   SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09     — secure
#   SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09    — secure
#   SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09 — secure
#   SecurityPolicy_TLS13_1_3_2025_09      — secure
#   SecurityPolicy_TLS13_1_3_FIPS_2025_09 — secure
#
# References:
#   https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html
#   https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/apigateway/types#SecurityPolicy
secure_security_policies := [
	"TLS_1_2",
	"SecurityPolicy_TLS12_*_EDGE",
	"SecurityPolicy_TLS13_*",
]

# is_outdated_security_policy is true when the given policy value is known
# (resolvable) and does not match any of the secure_security_policies patterns.
# Unresolvable values yield no result, preventing false positives on
# configurations that cannot be statically analysed.
is_outdated_security_policy(policy) if {
	value.is_known(policy)
	not _is_secure_security_policy(policy)
}

_is_secure_security_policy(policy) if {
	some pattern in secure_security_policies
	glob.match(pattern, [], policy.value)
}
