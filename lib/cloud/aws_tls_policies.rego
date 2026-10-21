# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.aws.tls_policies

import rego.v1

# Each set lists the predefined policies that do not allow TLS versions below 1.2.
# A policy missing from its set is reported, so a new policy needs to be added here.

# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
# https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html
elb_secure_policies := {
	"ELBSecurityPolicy-TLS13-1-3-2021-06",
	"ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
	"ELBSecurityPolicy-TLS-1-2-2017-01",
	"ELBSecurityPolicy-TLS13-1-3-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Res-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-RFC9151-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-RFC9151-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-Ext0-RFC9151-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP1-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP2-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP3-FIPS-2023-07",
	"ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP4-FIPS-2023-07",
	"ELBSecurityPolicy-FS-1-2-Res-2020-10",
	"ELBSecurityPolicy-FS-1-2-Res-2019-08",
	"ELBSecurityPolicy-FS-1-2-2019-08",
}

# The developer guide omits some policies, the SDK enum has all of them.
# https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/apigateway/types#SecurityPolicy
apigateway_secure_policies := {
	"TLS_1_2",
	"SecurityPolicy_TLS13_1_3_2025_09",
	"SecurityPolicy_TLS13_1_3_FIPS_2025_09",
	"SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_Ext2_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_Ext2_FIPS_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_PQ_2025_09",
	"SecurityPolicy_TLS13_1_2_2021_06",
	"SecurityPolicy_TLS13_2025_EDGE",
	"SecurityPolicy_TLS12_PFS_2025_EDGE",
	"SecurityPolicy_TLS12_2018_EDGE",
}

# https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DomainEndpointOptions.html
elasticsearch_secure_policies := {
	"Policy-Min-TLS-1-2-2019-07",
	"Policy-Min-TLS-1-2-PFS-2023-10",
	"Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08",
}
