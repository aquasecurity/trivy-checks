# trivy-checks

_trivy-checks_ contains misconfiguration checks for Trivy

_trivy-checks_ is an [Aqua Security](https://aquasec.com) open source project.
Learn about our open source work and portfolio [here](https://www.aquasec.com/products/open-source-projects/).
Join the community, and talk to us about any matter in [GitHub Discussion](https://github.com/aquasecurity/trivy/discussions).

## Project Layout

The directory structure is broken down as follows:

- `checks/` - the checks themselves, grouped by target: `cloud/<provider>/<service>/`, `docker/`, `kubernetes/`.
- `lib/` - shared Rego helpers the checks import: `lib/cloud`, `lib/kubernetes`, `lib/docker`, `lib/test`.
- `avd_docs/` - documentation generated from the check examples by `make docs`, published on [avd.aquasec.com](https://avd.aquasec.com/).
- `commands/` - [Node-collector](https://github.com/aquasecurity/k8s-node-collector) commands.
- `pkg/compliance/` - compliance report specs, one yaml per report ID.
- `cmd/` - development tools, e.g. `cmd/id` for the next free check ID and `cmd/avd_generator` behind `make docs`.
- `examples/` - sample IaC and custom checks used by the integration tests.
- `integration/` - integration tests that run real Trivy.
- `test/` - Go tests over the checks and their metadata.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to write a check.
