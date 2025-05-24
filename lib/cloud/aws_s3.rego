# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: cloud
package lib.aws.s3

import rego.v1

public_acls := {
	"public-read", "public-read-write",
	"website", "authenticated-read",
}

bucket_has_public_exposure_acl(bucket) if {
	bucket.acl.value in public_acls
	isManaged(bucket.publicaccessblock)
	not bucket.publicaccessblock.ignorepublicacls.value
	not bucket.publicaccessblock.blockpublicacls.value
}

bucket_has_public_exposure_acl(bucket) if {
	bucket.acl.value in public_acls
	not bucket.publicaccessblock
}
