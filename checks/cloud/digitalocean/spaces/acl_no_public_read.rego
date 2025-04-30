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
#   id: AVD-DIG-0006
#   avd_id: AVD-DIG-0006
#   provider: digitalocean
#   service: spaces
#   severity: CRITICAL
#   short_code: acl-no-public-read
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
