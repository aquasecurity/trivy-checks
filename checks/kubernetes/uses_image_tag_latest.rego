# METADATA
# title: "Image tag \":latest\" used"
# description: "It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/configuration/overview/#container-images
# custom:
#   id: KSV013
#   avd_id: AVD-KSV-0013
#   severity: MEDIUM
#   short_code: use-specific-tags
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

# is_container_tagged checks if a container has a tag or digest.
# It returns true if the image contains a digest (indicated by '@'), or if the tag is not "latest".
is_container_tagged(container) if contains(container.image, "@")

is_container_tagged(container) if {
	# No digest, look at tag
	[_, tag] := split(container.image, ":")
	tag != "latest"
}

# untagged_containers returns the names of all containers which
# have untagged images or images with the latest tag.
untagged_containers contains container if {
	some container in kubernetes.containers
	not is_container_tagged(container)
}

deny contains res if {
	some container in untagged_containers
	msg := kubernetes.format(sprintf(
		"Container '%s' of %s '%s' should specify an image tag",
		[container.name, kubernetes.kind, kubernetes.name],
	))
	res := result.new(msg, container)
}
