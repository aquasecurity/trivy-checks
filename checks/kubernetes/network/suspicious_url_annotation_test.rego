package builtin.kubernetes.kcv0094_test

import data.builtin.kubernetes.kcv0094 as check

import rego.v1

test_check[name] if {
	some name, tc in {
		"valid url": {
			"key": "link.argocd.argoproj.io/external-link",
			"value": "https://valid-url.com",
			"expected": 0,
		},
		"suspicious characters": {
			"key": "link.argocd.argoproj.io/external-link",
			"value": "http://example.com/#;\ninjection_point",
			"expected": 1,
		},
		"unsupported annotation": {
			"key": "foo",
			"value": "http://example.com/#;\ninjection_point",
			"expected": 0,
		},
		"alb oidc": {
			"key": "alb.ingress.kubernetes.io/auth-idp-oidc",
			"value": `'{"issuer":"https://example.com","authorizationEndpoint":"http://example.com/#;\ninjection_point","tokenEndpoint":"https://token.example.com","userInfoEndpoint":"https://userinfo.example.com","secretName":"my-k8s-secret"}'`,
			"expected": 1,
		},
	}

	r := check.deny with input as {
		"apiVersion": "v1",
		"kind": "test",
		"metadata": {
			"namespace": "default",
			"annotations": {tc.key: tc.value},
		},
	}

	count(r) == tc.expected
}
