package lib.aws.apigateway_test

import rego.v1

import data.lib.aws.apigateway as apigateway

# Every currently documented secure API Gateway / SAM domain security policy.
secure_policies := [
	"TLS_1_2",
	"SecurityPolicy_TLS12_2018_EDGE",
	"SecurityPolicy_TLS12_PFS_2025_EDGE",
	"SecurityPolicy_TLS13_1_3_2025_09",
	"SecurityPolicy_TLS13_1_3_FIPS_2025_09",
	"SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_2021_06",
	"SecurityPolicy_TLS13_2025_EDGE",
]

test_outdated_tls_1_0 if {
	apigateway.is_outdated_security_policy({"value": "TLS_1_0"})
}

test_secure_policies_are_not_outdated if {
	every p in secure_policies {
		not apigateway.is_outdated_security_policy({"value": p})
	}
}

test_unresolvable_policy_is_not_outdated if {
	not apigateway.is_outdated_security_policy({"value": "", "unresolvable": true})
}

test_future_family_members_are_not_outdated if {
	not apigateway.is_outdated_security_policy({"value": "SecurityPolicy_TLS12_NEW_EDGE"})
	not apigateway.is_outdated_security_policy({"value": "SecurityPolicy_TLS13_FUTURE_2099_01"})
}
