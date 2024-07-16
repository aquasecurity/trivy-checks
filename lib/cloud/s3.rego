package lib.s3

import rego.v1

public_acls = {"public-read", "public-read-write", "website", "authenticated-read"}

bucket_has_public_access(bucket) if {
	bucket.acl.value in public_acls
	not bucket.publicaccessblock.ignorepublicacls.value
	not bucket.publicaccessblock.blockpublicacls.value
}
