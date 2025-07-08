# METADATA
# title: Spaces bucket or bucket object has public read acl set
# description: |
#   Space bucket and bucket object permissions should be set to deny public access unless explicitly required.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.digitalocean.com/reference/api/spaces-api/#access-control-lists-acls
# custom:
#   id: DIG-0006
#   aliases:
#     - AVD-DIG-0006
#     - acl-no-public-read
#   long_id: digitalocean-spaces-acl-no-public-read
#   provider: digitalocean
#   service: spaces
#   severity: CRITICAL
#   recommended_action: Apply a more restrictive ACL
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: spaces
#             provider: digitalocean
#   examples: checks/cloud/digitalocean/spaces/acl_no_public_read.yaml
package builtin.digitalocean.spaces.digitalocean0006

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some bucket in input.digitalocean.spaces.buckets
	value.is_equal(bucket.acl, "public-read")
	res := result.new("Bucket is publicly exposed.", bucket.acl)
}

deny contains res if {
	some bucket in input.digitalocean.spaces.buckets
	some object in bucket.objects
	object.acl.value == "public-read"
	value.is_equal(object.acl, "public-read")
	res := result.new("Object is publicly exposed.", object.acl)
}
