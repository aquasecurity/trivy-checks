# trivy-checks

_trivy-checks_ contains misconfiguration checks for Trivy

_trivy-checks_ is an [Aqua Security](https://aquasec.com) open source project.
Learn about our open source work and portfolio [here](https://www.aquasec.com/products/open-source-projects/).
Join the community, and talk to us about any matter in [GitHub Discussion](https://github.com/aquasecurity/trivy/discussions).

## Project Layout

The directory structure is broken down as follows:

- `cmd/` - These CLI tools are primarily used during development for end-to-end testing without requiring the use of a library.
  - `cmd/id` - This command helps generate the next available ID that is free when writing a new check.
- `checks/` - All the checks are defined in this directory.
  - `kubernetes/` - Kubernetes-specific security checks
    - `access/` - RBAC, authentication, and authorization related checks
    - `network/` - Network security checks including network policies, host network access, and service configurations
    - `resources/` - Resource quotas, limits, and management checks
    - `security/` - Core security checks including Pod Security Standards
    - `workloads/` - Workload-specific security checks
  - `cloud/kubernetes/` - Cloud-specific Kubernetes security checks
- `commands/` - All [Node-collector](https://github.com/aquasecurity/k8s-node-collector) commands are defined in this directory.
- `test/` - Integration tests and other high-level tests that require a full build of the project.
