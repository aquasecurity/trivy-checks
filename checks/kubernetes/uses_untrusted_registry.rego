# METADATA
# title: Restrict container images to trusted registries
# description: Ensure that all containers use images only from trusted registry domains.
# scope: package
# schemas:
# - input: schema.kubernetes
# related_resources:
# - https://cloud.google.com/container-registry/docs/overview#registries
# - https://docs.aws.amazon.com/general/latest/gr/ecr.html
# custom:
#   id: KSV0125
#   avd_id: AVD-KSV-0125
#   severity: MEDIUM
#   short_code: use-trusted-registry
#   recommended_action: Use images from trusted registries.
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
package builtin.kubernetes.KSV0125

import rego.v1

import data.lib.kubernetes

import data.ksv0125

azure_registries := {"azurecr.io"}

ecr_registries := {
	"ecr.us-east-2.amazonaws.com",
	"ecr.us-east-1.amazonaws.com",
	"ecr.us-west-1.amazonaws.com",
	"ecr.us-west-2.amazonaws.com",
	"ecr.af-south-1.amazonaws.com",
	"ecr.ap-east-1.amazonaws.com",
	"ecr.ap-south-1.amazonaws.com",
	"ecr.ap-northeast-2.amazonaws.com",
	"ecr.ap-southeast-1.amazonaws.com",
	"ecr.ap-southeast-2.amazonaws.com",
	"ecr.ap-northeast-1.amazonaws.com",
	"ecr.ca-central-1.amazonaws.com",
	"ecr.cn-north-1.amazonaws.com.cn",
	"ecr.cn-northwest-1.amazonaws.com.cn",
	"ecr.eu-central-1.amazonaws.com",
	"ecr.eu-west-1.amazonaws.com",
	"ecr.eu-west-2.amazonaws.com",
	"ecr.eu-south-1.amazonaws.com",
	"ecr.eu-west-3.amazonaws.com",
	"ecr.eu-north-1.amazonaws.com",
	"ecr.me-south-1.amazonaws.com",
	"ecr.sa-east-1.amazonaws.com",
	"ecr.us-gov-east-1.amazonaws.com",
	"ecr.us-gov-west-1.amazonaws.com",
}

# list of trusted GCR registries
gcr_registries := {
	"gcr.io",
	"us.gcr.io",
	"eu.gcr.io",
	"asia.gcr.io",
}

default_trusted_registries := (azure_registries | ecr_registries) | gcr_registries

all_trusted_registires := ksv0125.trusted_registries if {
	count(ksv0125.trusted_registries) > 0
} else := default_trusted_registries

container_image_from_untrusted_registry(container) if {
	image_parts := split(container.image, "/")
	count(image_parts) > 1
	registry = image_parts[0]
	not is_registry_trusted(registry)
}

is_registry_trusted(registry) if {
	some trusted in all_trusted_registires
	endswith(registry, trusted)
}

deny contains res if {
	some container in kubernetes.containers
	container_image_from_untrusted_registry(container)
	msg := kubernetes.format(sprintf(
		"Container %s in %s %s (namespace: %s) uses an image from an untrusted registry.",
		[container.name, lower(kubernetes.kind), kubernetes.name, kubernetes.namespace],
	))
	res := result.new(msg, container)
}
