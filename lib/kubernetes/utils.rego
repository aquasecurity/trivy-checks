# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: kubernetes
#     - type: rbac
package lib.utils

import rego.v1

has_key(x, k) if {
	_ = x[k]
}
