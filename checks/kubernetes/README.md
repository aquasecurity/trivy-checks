## Comprehensive REGO library for Kubernetes workload configuration checks

Examples:
- Use our REGO checks with tools such as OPA Gatekeeper and Conftest to check kubernetes resources configurations
- Ensure pods and controllers are not running as privileged
- Ensure pods images are hosted in a trusted ECR/GCR/ACR registry
- And more checks to comply with PSP, PSS and additional standards

# Quick start
Follow these steps to pull a policy and test Kubernetes workload manifest:

1. Create a directory named "myPolicy" to host all the required rego checks

```
mkdir myPolicy
```
2. Download the main library and the desired checks(s) into "myPolicy" directory - in this example we use the "host_ipc" check only
```
wget https://github.com/aquasecurity/trivy-checks/raw/main/lib/kubernetes/kubernetes.rego
wget https://github.com/aquasecurity/trivy-checks/raw/main/lib/kubernetes/utils.rego
wget https://github.com/aquasecurity/trivy-checks/raw/main/checks/kubernetes/pss/baseline/1_host_ipc.rego
```
3. Download an example of a non-compliant kubernetes deployment (in yaml format) 
```
wget https://github.com/aquasecurity/trivy-checks/raw/main/test/testdata/kubernetes/KSV008/denied.yaml
```
4. Use any tool that supports REGO to test the example file. In this example we are using conftest
```
conftest test denied.yaml --policy myPolicy/ --namespace builtin.kubernetes.KSV008
```