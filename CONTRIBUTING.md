# Contributing

Welcome, and thank you for considering contributing to trivy-checks!

This guide covers what is specific to this repository, from how a check is laid out to what CI verifies. If something is missing, or you get stuck, please [start a discussion](https://github.com/aquasecurity/trivy/discussions/new) and we'll do our best to help.

Background reading that is not repeated here:

- [Contribute Rego Checks](https://trivy.dev/docs/latest/community/contribute/checks/overview/) for a general overview.
- [Custom checks](https://trivy.dev/docs/latest/guide/scanner/misconfiguration/custom/) for the check metadata reference, [schemas](https://trivy.dev/docs/latest/guide/scanner/misconfiguration/custom/schema/) and [testing](https://trivy.dev/docs/latest/guide/scanner/misconfiguration/custom/testing/).
- The [OPA documentation](https://www.openpolicyagent.org/docs/policy-language/) to learn Rego, and the [Rego Playground](https://play.openpolicyagent.org/) to try things out.
- The [OPA Slack](https://slack.openpolicyagent.org/) for questions about Rego itself.

## Prerequisites

- **Go**, the version from `go.mod`.
- **[Regal](https://github.com/open-policy-agent/regal)**.
- **jq**.
- **Docker**.
- **GNU sed**, installed as `gsed` on macOS.

Do not reach for a stock `opa` binary. The checks call built-in functions that plain OPA does not
have, such as `result.new`, `isManaged`, `cidr.is_public` and `sh.parse_commands`. Every `make`
target goes through `go run ./cmd/opa`, an OPA build with all of these registered, and that is the
only way to compile or test a check locally.

## Writing checks

### Anatomy of a check

Up to three hand-written files live side by side, and the documentation is generated from them:

```
checks/cloud/azure/appservice/web_app_https_only.rego       # the check
checks/cloud/azure/appservice/web_app_https_only_test.rego  # unit tests
checks/cloud/azure/appservice/web_app_https_only.yaml       # good/bad examples
avd_docs/azure/appservice/AZU-0072/docs.md                  # generated, do not edit by hand
avd_docs/azure/appservice/AZU-0072/Terraform.md             # generated from the examples
```

Checks are grouped by target. Cloud providers live in `checks/cloud`, Dockerfiles in
`checks/docker` and Kubernetes manifests in `checks/kubernetes`.

### Verify the provider and service exist

Cloud checks read from a data structure that Trivy builds from the scanned input, so the provider
and service you target must already be supported. Look for them in
[`pkg/iac/providers`](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/providers) in the
Trivy repository. If the service or the property you need is missing, add it first. See
[Add Service Support](https://trivy.dev/docs/latest/community/contribute/checks/service-support/),
and note that this change goes to the Trivy repository, not to this one.

Kubernetes and Dockerfile checks need no provider definitions.

### Pick an ID

Run `make id`. It prints the next free ID for every prefix in use, so take the one that matches
the target you are writing for.

### Write the check

```rego
# METADATA
# title: Web App Accepting Traffic Other Than HTTPS
# description: |
#   Allowing HTTP undermines transport encryption and exposes user data.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#https_only
# custom:
#   id: AZU-0072
#   long_id: azure-appservice-web-app-https-only
#   aliases:
#     - AVD-AZU-0072
#     - web-app-https-only
#     - azure-appservice-web-app-https-only
#   provider: azure
#   service: appservice
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   recommended_action: Set 'HTTPS Only' to true in App Service TLS settings to force encrypted transport.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: appservice
#             provider: azure
#   examples: checks/cloud/azure/appservice/web_app_https_only.yaml
package builtin.azure.appservice.azure0072

import rego.v1

deny contains res if {
	some service in input.azure.appservice.services
	isManaged(service)
	not service.httpsonly.value
	res := result.new(
		"App service does not have HTTPS enforced.",
		object.get(service, "httpsonly", service),
	)
}
```

This is a real check, and you can find it in
`checks/cloud/azure/appservice/web_app_https_only.rego`.

#### Package name

There is no strict rule. Follow the checks that already live in the same directory:

```
AZU-0072   ->  builtin.azure.appservice.azure0072
AWS-0176   ->  builtin.aws.rds.aws0176
KSV-01010  ->  builtin.kubernetes.KSV01010
DS-0006    ->  builtin.dockerfile.DS006
```

Cloud checks are lowercase and carry the service. Kubernetes and Dockerfile checks have no service
and keep the ID uppercase.

#### Syntax

Checks use Rego v1, so write `deny contains res if { ... }` with `import rego.v1`. CI rejects the
old `deny[res] { ... }` form.

#### Helpers

`result.new` and `isManaged` come from the runtime and need no import. The second argument of
`result.new` is the value the finding points at, and that is what gives the finding its line
numbers.

Prefer the helpers in `lib/` over raw comparisons. `lib/cloud/value.rego` deals with values Trivy
could not resolve. For such a value `value.is_equal`, `value.is_true`, `value.greater_than` and
friends evaluate to `false`, so the check stays silent instead of reporting a false positive. Take
care when negating them, because `not value.is_true(x)` succeeds for an unresolvable `x` and
brings the false positive back. Guard that case with `value.is_known`. `lib/cloud/metadata.rego`
provides `metadata.obj_by_path` for pointing a finding at a nested attribute that may be absent.

The `schemas` annotation validates your input references against the Trivy schema, which catches
typos in property paths early. `related_resources` and `minimum_trivy_version` are optional. The
example sets the latter because App Service support arrived in Trivy at the same time, see
[`minimum_trivy_version`](#minimum_trivy_version) below.

### Metadata fields

Metadata is yaml inside a Rego comment, and it is
[part of Rego itself](https://www.openpolicyagent.org/docs/policy-language/#metadata). Built-in
checks must have it.

`make lint-rego` rejects any field under `custom` that is not listed below, using the schema in
[`.regal/rules/custom/invalid-metadata`](.regal/rules/custom/invalid-metadata/invalid_metadata.rego).
That schema only insists on `id` and `input`; the other required fields are conventions that every
built-in check follows.

| Field | Required | Description |
| --- | --- | --- |
| `id` | yes | The ID from `make id`. |
| `input.selector` | yes | Which inputs the check applies to. Cloud checks select `type: cloud` and narrow by `provider` and `service`, Kubernetes checks select `type: kubernetes` and narrow by `kind`, Dockerfile checks select `type: dockerfile`. Limiting the subtypes keeps scans fast. |
| `long_id` | yes | Stable human-readable ID in the form `provider-service-short-description`. |
| `aliases` | yes | Previously used IDs, including the `AVD-` prefixed one. Keep old IDs here so existing ignore files keep working. |
| `severity` | yes | One of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `recommended_action` | yes | What the user should do to resolve the finding. `recommended_actions` is an older spelling that is still accepted, but do not set both. |
| `provider`, `service` | cloud only | Must match the directory names under `pkg/iac/providers` in Trivy. Kubernetes and Dockerfile checks set neither. |
| `examples` | no | Path to the yaml examples file, for checks that have one. |
| `minimum_trivy_version` | no | The first Trivy release whose data model the check can rely on. Valid semver, see [below](#minimum_trivy_version). |
| `deprecated` | no | Set to `true` rather than deleting a check that is no longer wanted, so its ID stays taken and existing ignore rules keep resolving. Trivy skips deprecated checks unless the scan passes `--include-deprecated-checks`. |
| `frameworks` | no | Maps the check to compliance controls, e.g. `cis-aws-1.4: ["4.6"]`. See [Writing compliance reports](#writing-compliance-reports). |
| `terraform`, `cloud_formation` | no | Legacy per-engine `links`, `good_examples` and `bad_examples`. Superseded by the yaml examples file, so no new check needs them. |

#### minimum_trivy_version

Checks are validated against the schemas of several Trivy versions, and at scan time they run
against whatever data model the installed Trivy builds. A check that reads a field an older model
does not have would break on both counts, and `minimum_trivy_version` declares the first release
it can rely on. `make check-rego-matrix` skips the check for every version below that, and Trivy
does the same when scanning.

Set it when the check needs a model Trivy has only just gained, either because the check is
written together with new provider support, or because it starts reading a field that came with a
change on the Trivy side.

The value is normally a release that does not exist yet rather than the one you have installed.
Until it ships, the integration tests cover the check with the `canary` image, or with your own
build of Trivy through `TRIVY_BINARY` (see [Run the check with Trivy](#run-the-check-with-trivy)).
Bump the value if the change slips to a later release.

### Add examples

Examples live in a yaml file next to the check. Each top-level key is an engine, one of
`terraform`, `cloudformation`, `kubernetes` or `dockerfile`, and a check may declare several.
Terraform is by far the most common:

```yaml
terraform:
  links:
    - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#https_only
  good:
    - |-
      resource "azurerm_app_service" "good_example" {
        https_only = true
      }
  bad:
    - |-
      resource "azurerm_app_service" "bad_example" {
        https_only = false
      }
```

The integration tests scan these examples, and `make docs` renders them into `avd_docs`, which is
what ends up on [avd.aquasec.com](https://avd.aquasec.com/). Only `terraform` and `cloudformation`
get a page there (`Terraform.md`, `CloudFormation.md`), while the other two engines are used by
the tests only.

Add a `good` example for every configuration the check is meant to accept, and a `bad` one for
every configuration it is meant to reject, including the case where the attribute is omitted and
the default applies.

### Add tests

Tests live next to the check in `NAME_test.rego`, in the package of the check with a `_test`
suffix:

```rego
package builtin.azure.appservice.azure0072_test

import rego.v1

import data.builtin.azure.appservice.azure0072 as check

test_deny_https_disabled if {
	inp := {"azure": {"appservice": {"services": [{"httpsonly": {"value": false}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_https_enabled if {
	inp := {"azure": {"appservice": {"services": [{"httpsonly": {"value": true}}]}}}
	res := check.deny with input as inp
	res == set()
}
```

Cover the denied case, the allowed case, and, when the check reads a value that may be
unresolvable, an input with `{"value": "", "unresolvable": true}` to prove it produces no finding.

Many existing tests use the assertion helpers from `lib/test` (`import data.lib.test`). They print
the actual value when a test fails, which a bare comparison does not:

```rego
test.assert_count(check.deny, 1) with input as inp
test.assert_empty(check.deny) with input as inp
test.assert_equal_message("App service does not have HTTPS enforced.", check.deny) with input as inp
```

### Run the check with Trivy

Unit tests only cover handcrafted input. To see the check work end to end on real configuration
files, build the checks into a bundle and point Trivy at it:

```bash
make start-registry  # local OCI registry on port 5111
make push-bundle     # builds bundle.tar.gz and pushes it there
trivy conf --checks-bundle-repository localhost:5111/trivy-checks:latest ./path/to/terraform
make stop-registry
```

The integration tests do the same thing under the hood. Do not reach for `--config-check` instead.
Trivy already ships these checks, and loading them a second time fails with
`rego_type_error: package annotation redeclared`.

When the check depends on a Trivy change that is not released yet, build Trivy from your branch
and run the examples test against that binary:

```bash
TRIVY_BINARY=/path/to/trivy go test -tags=integration -run TestScanCheckExamples ./integration/
```

The test then makes a single pass with your build instead of the pinned release images, so there
is no need to build and push a Trivy image first. Filtering by `minimum_trivy_version` follows the
version the binary reports, and a prerelease version is never filtered out, so a check written for
the upcoming release still runs. Docker is needed either way, since the bundle is served from a
local registry in both modes.

## Before opening a PR

`make rego` runs the fast loop: `fmt-rego`, `check-rego`, `lint-rego`, `test-rego` and `docs`. The
remaining commands are not part of it and have to be run separately.

| Command | What it does | CI job |
| --- | --- | --- |
| `make fmt-rego` | Formats the Rego in `lib`, `checks` and `examples`. | Test Rego |
| `make check-rego` | Validates syntax and input references against the latest Trivy schema. | Test Rego |
| `make lint-rego` | Runs Regal, including this repository's custom rules in `.regal/rules`. | Test Rego |
| `make test-rego` | Runs the Rego unit tests. | Test Rego |
| `make docs` | Reformats the yaml examples and regenerates `avd_docs` from them. | Test Docs |
| `make check-rego-matrix` | Validates the checks against the schemas of every version in `TRIVY_VERSIONS`, taking `minimum_trivy_version` into account. | Test Rego |
| `make test` | Runs the Go tests. | Test Go |
| `make test-integration` | Scans the yaml examples with several real Trivy versions, `canary` included, or with your own build via `TRIVY_BINARY`. Needs Docker and takes a few minutes. | Integration Tests |

`make fmt-rego` and `make docs` change files instead of reporting problems. CI reruns both and
fails on any diff, so commit everything they touch, including the reformatted yaml examples.

## Writing compliance reports

To write a compliance report please check the following [compliance guide](./pkg/compliance/README.md).

The supported reports are the yaml files in [`pkg/compliance`](./pkg/compliance), each named after
its report ID.
