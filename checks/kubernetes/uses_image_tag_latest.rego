# METADATA
# title: "Image tag \":latest\" used"
# description: "It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/configuration/overview/#container-images
# custom:
#   id: KSV-0013
#   long_id: kubernetes-use-specific-tags
#   aliases:
#     - AVD-KSV-0013
#     - KSV013
#     - use-specific-tags
#   severity: MEDIUM
#   recommended_action: "Use a specific container image tag that is not 'latest'."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
#         - kind: replicaset
#         - kind: replicationcontroller
#         - kind: deployment
#         - kind: deploymentconfig
#         - kind: statefulset
#         - kind: daemonset
#         - kind: cronjob
#         - kind: job
package builtin.kubernetes.KSV013

import rego.v1

import data.lib.kubernetes

# is_image_tagged returns true if the image contains a digest ("@...").
# A digest makes the image immutable regardless of whether a tag is present.
is_image_tagged(image) if contains(image, "@")

# is_image_tagged returns true if the image has an explicit tag (":...") other than "latest".
# The check is performed on the last path segment after the last "/", to avoid mistaking a registry port for a tag.
is_image_tagged(image) if {
	no_digest := split(image, "@")[0]
	path_parts := split(no_digest, "/")
	last := path_parts[count(path_parts) - 1]
	tag_parts := split(last, ":")
	count(tag_parts) > 1
	tag := tag_parts[count(tag_parts) - 1]
	tag != "latest"
}

# untagged_containers returns the names of all containers which
# have untagged images or images with the latest tag.
untagged_containers contains container if {
	some container in kubernetes.containers
	not is_image_tagged(container.image)
}

deny contains res if {
	some container in untagged_containers
	msg := kubernetes.format(sprintf(
		"Container '%s' of %s '%s' should specify an image tag",
		[container.name, kubernetes.kind, kubernetes.name],
	))
	res := result.new(msg, container)
}
