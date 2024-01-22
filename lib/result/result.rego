# METADATA
# custom:
#   library: true
package lib.result

new(message, metadata) = result {
	result := {
		"metadata": metadata,
		"msg": message,
	}
}

is_managed(cause) = res {
	metadata := get_metadata(cause)
	res := metadata.managed
}

get_metadata(cause) = metadata {
	metadata := object.get(cause, "__defsec_metadata", cause)
}
