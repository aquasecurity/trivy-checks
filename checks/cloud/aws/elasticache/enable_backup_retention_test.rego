package builtin.aws.elasticache.aws0050_test

import rego.v1

import data.builtin.aws.elasticache.aws0050 as check
import data.lib.test

test_allow_retention_limit_greater_than_zero if {
	inp := {"aws": {"elasticache": {"clusters": [{
		"engine": {"value": "redis"},
		"nodetype": {"value": "cache.t3.micro"},
		"snapshotretentionlimit": {"value": 1},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_retention_limit_zero_but_engine_is_not_redis if {
	inp := {"aws": {"elasticache": {"clusters": [{
		"engine": {"value": "memcached"},
		"nodetype": {"value": "cache.t3.micro"},
		"snapshotretentionlimit": {"value": 0},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_retention_limit_zero_but_nodetype_is_t1micro if {
	inp := {"aws": {"elasticache": {"clusters": [{
		"engine": {"value": "redis"},
		"nodetype": {"value": "cache.t1.micro"},
		"snapshotretentionlimit": {"value": 0},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_retention_limit_zero if {
	inp := {"aws": {"elasticache": {"clusters": [{
		"engine": {"value": "redis"},
		"nodetype": {"value": "cache.t3.micro"},
		"snapshotretentionlimit": {"value": 0},
	}]}}}

	test.assert_equal_message("Cluster snapshot retention is not enabled.", check.deny) with input as inp
}
