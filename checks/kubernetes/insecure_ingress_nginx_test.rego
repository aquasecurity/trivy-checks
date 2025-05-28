package builtin.kubernetes.kcv0093

import rego.v1

# Tests for auth-url annotation
test_invalid_auth_url_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-invalid-url",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/auth-url": "http://example.com/invalid|url"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 1
	r[_].msg == "Pod has a nginx.ingress.kubernetes.io/auth-url annotation containing suspicious characters"
}

test_suspicious_char_auth_url_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-suspicious-char",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/auth-url": "http://example.com/#;\ninjection_point"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 1
	r[_].msg == "Pod has a nginx.ingress.kubernetes.io/auth-url annotation containing suspicious characters"
}

test_valid_auth_url_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-valid-url",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/auth-url": "https://valid-url.com"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 0
}

# Tests for auth-tls-match-cn annotation
test_invalid_auth_tls_match_cn_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-invalid-cn",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/auth-tls-match-cn": "CN=invalid|cn"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 1
	r[_].msg == "Pod has a nginx.ingress.kubernetes.io/auth-tls-match-cn annotation containing suspicious characters"
}

test_suspicious_char_auth_tls_match_cn_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-suspicious-char-cn",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/auth-tls-match-cn": "CN=valid#;\ninjection_point"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 1
	r[_].msg == "Pod has a nginx.ingress.kubernetes.io/auth-tls-match-cn annotation containing suspicious characters"
}

test_valid_auth_tls_match_cn_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-valid-cn",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/auth-tls-match-cn": "CN=valid-cn"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 0
}

# Tests for mirror-target annotation
test_invalid_mirror_target_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-invalid-target",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/mirror-target": "http://example.com/invalid|url"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 1
	r[_].msg == "Pod has a nginx.ingress.kubernetes.io/mirror-target annotation containing suspicious characters"
}

test_suspicious_char_mirror_target_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-suspicious-char-target",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/mirror-target": "http://example.com/#;\ninjection_point"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 1
	r[_].msg == "Pod has a nginx.ingress.kubernetes.io/mirror-target annotation containing suspicious characters"
}

test_valid_mirror_target_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-valid-target",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/mirror-target": "https://valid-url.com"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 0
}

# Tests for mirror-host annotation
test_invalid_mirror_host_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-invalid-host",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/mirror-host": "http://example.com/invalid|url"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 1
	r[_].msg == "Pod has a nginx.ingress.kubernetes.io/mirror-host annotation containing suspicious characters"
}

test_suspicious_char_mirror_host_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-suspicious-char-host",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/mirror-host": "http://example.com/#;\ninjection_point"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 1
	r[_].msg == "Pod has a nginx.ingress.kubernetes.io/mirror-host annotation containing suspicious characters"
}

test_valid_mirror_host_annotation if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Ingress",
		"metadata": {
			"name": "test-ingress-valid-host",
			"namespace": "default",
			"annotations": {"nginx.ingress.kubernetes.io/mirror-host": "https://valid-url.com"},
		},
		"spec": {"ingressClassName": "nginx"},
	}

	count(r) == 0
}
