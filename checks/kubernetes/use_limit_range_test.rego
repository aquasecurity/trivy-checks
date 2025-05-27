package builtin.kubernetes.KSV039

import rego.v1

test_use_limit_range_configure if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "core-resource-limits"},
		"spec": {"limits": [
			{
				"type": "Pod",
				"max": {
					"cpu": "2",
					"memory": "1Gi",
				},
				"min": {
					"cpu": "200m",
					"memory": "6Mi",
				},
			},
			{
				"type": "Container",
				"max": {
					"cpu": "2",
					"memory": "1Gi",
				},
				"min": {
					"cpu": "100m",
					"memory": "4Mi",
				},
				"default": {
					"cpu": "300m",
					"memory": "200Mi",
				},
				"defaultRequest": {
					"cpu": "200m",
					"memory": "100Mi",
				},
				"maxLimitRequestRatio": {"cpu": "10"},
			},
		]},
	}

	count(r) == 0
}

test_use_limit_range_no_limits if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "core-resource-limits"},
		"spec": {},
	}

	r[_].msg == "A LimitRange policy with a default requests and limits for each container should be configured"
}

test_use_limit_range_no_min if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "core-resource-limits"},
		"spec": {"limits": [
			{
				"type": "Pod",
				"max": {
					"cpu": "2",
					"memory": "1Gi",
				},
			},
			{
				"type": "Container",
				"max": {
					"cpu": "2",
					"memory": "1Gi",
				},
				"default": {
					"cpu": "300m",
					"memory": "200Mi",
				},
				"defaultRequest": {
					"cpu": "200m",
					"memory": "100Mi",
				},
				"maxLimitRequestRatio": {"cpu": "10"},
			},
		]},
	}

	r[_].msg == "A LimitRange policy with a default requests and limits for each container should be configured"
}

test_use_limit_range_no_max if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "core-resource-limits"},
		"spec": {"limits": [
			{
				"type": "Pod",
				"min": {
					"cpu": "200m",
					"memory": "6Mi",
				},
			},
			{
				"type": "Container",
				"min": {
					"cpu": "100m",
					"memory": "4Mi",
				},
				"default": {
					"cpu": "300m",
					"memory": "200Mi",
				},
				"defaultRequest": {
					"cpu": "200m",
					"memory": "100Mi",
				},
				"maxLimitRequestRatio": {"cpu": "10"},
			},
		]},
	}

	r[_].msg == "A LimitRange policy with a default requests and limits for each container should be configured"
}

test_use_limit_range_no_default if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "core-resource-limits"},
		"spec": {"limits": [
			{
				"type": "Pod",
				"max": {
					"cpu": "2",
					"memory": "1Gi",
				},
				"min": {
					"cpu": "200m",
					"memory": "6Mi",
				},
			},
			{
				"type": "Container",
				"max": {
					"cpu": "2",
					"memory": "1Gi",
				},
				"min": {
					"cpu": "100m",
					"memory": "4Mi",
				},
				"defaultRequest": {
					"cpu": "200m",
					"memory": "100Mi",
				},
				"maxLimitRequestRatio": {"cpu": "10"},
			},
		]},
	}

	r[_].msg == "A LimitRange policy with a default requests and limits for each container should be configured"
}

test_use_limit_range_default_request if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "LimitRange",
		"metadata": {"name": "core-resource-limits"},
		"spec": {"limits": [
			{
				"type": "Pod",
				"max": {
					"cpu": "2",
					"memory": "1Gi",
				},
				"min": {
					"cpu": "200m",
					"memory": "6Mi",
				},
			},
			{
				"type": "Container",
				"max": {
					"cpu": "2",
					"memory": "1Gi",
				},
				"min": {
					"cpu": "100m",
					"memory": "4Mi",
				},
				"default": {
					"cpu": "300m",
					"memory": "200Mi",
				},
				"maxLimitRequestRatio": {"cpu": "10"},
			},
		]},
	}

	r[_].msg == "A LimitRange policy with a default requests and limits for each container should be configured"
}
