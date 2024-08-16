# Add New Compliance Report

## Define a Compliance spec, based on cis benchmark or other specs

here is an example for cis compliance report:

```yaml
---
spec:
  id: k8s-cis-1.23
  title: CIS Kubernetes Benchmarks v1.23
  description: CIS Kubernetes Benchmarks
  platform: k8s
  type: cis
  version: '1.23'
  relatedResources:
  - https://www.cisecurity.org/benchmark/kubernetes
  controls:
  - id: 1.1.1
    name: Ensure that the API server pod specification file permissions are set to
      600 or more restrictive
    description: Ensure that the API server pod specification file has permissions
      of 600 or more restrictive
    checks:
    - id: AVD-KCV-0073
    commands:
    - id: CMD-0001
    severity: HIGH

```

### Compliance ID

id field is the name used to execute the compliance scan via trivy
example:

```sh
trivy k8s --compliance k8s-cis-1.23
```

id naming convension: {platform}-{type}-{version}

### Compliance Platform

The platform field specifies the type of platform on which to run this compliance report.
supported platforms:

- k8s (native kubernetes cluster)
- eks (elastic kubernetes service)
- aks (azure kubernetes service)
- gke (google kubernetes engine)
- rke2 (rancher kubernetes engine v2)
- ocp (OpenShift Container Platform)
- docker (docker engine)
- aws (amazon web services)

### Compliance Type

The type field specifies the kind compliance report.

- cis (Center for Internet Security)
- nsa (National Security Agency)
- pss (Pod Security Standards)

### Compliance Version

The version field specifies the version of the compliance report.

- 1.23

### Compliance Check ID

Specify the check ID that needs to be evaluated based on the information collected from the command data output to assess the control.

Example of how to define check data under ./checks folder:

```sh
# METADATA
# title: "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive"
# description: "Ensure that the kubelet.conf file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0073
#   avd_id: AVD-KCV-0073
#   severity: HIGH
#   short_code: ensure-kubelet.conf-file-permissions-600-or-more-restrictive.
#   recommended_action: "Change the kubelet.conf file permissions to 600 or more restrictive if exist"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0073

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_file_permission(sp) := {"kubeletConfFilePermissions": violation} {
 sp.kind == "NodeInfo"
 sp.type == types[_]
 violation := {permission | permission = sp.info.kubeletConfFilePermissions.values[_]; permission > 600}
 count(violation) > 0
}

deny[res] {
 output := validate_kubelet_file_permission(input)
 msg := "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive"
 res := result.new(msg, output)
}
```

for additional info on writing checks look at [contribution guide](../CONTRIBUTING.md)

### Compliance Command ID

***Note:*** This field is not mandatory, it relevant to k8s compliance report when node-collector is in use

Specify the command ID (#ref) that needs to be executed to collect the information required to evaluate the control.

Example of how to define command data under ./commands folder:

```yaml
---
- id: CMD-0001
  key: kubeletConfFilePermissions
  title: kubelet.conf file permissions
  nodeType: worker
  audit: stat -c %a $kubelet.kubeconfig
  platfroms:
    - k8s
    - aks
```

#### Command ID

Find the next command ID by running the command.

```sh
make command-id
```

#### Command Key

- Re-use an existing key or specifiy a new one (make sure key name has no spaces)

Note: The key value should match the key name evaluated by the Rego check.

### Command Title

Represent the purpose of the command

### Command NodeType

Specify the node type on which the command is supposed to run.

- worker
- master

### Command Audit

Specifiy here the shell command to be used please make sure to add error supression (2>/dev/null)

### Command Platforms

The list of platforms that support this command , name should be taken from this list [Platforms](#compliance-platform)

### Command Config Files

The commands use a configuration file that helps obtain the paths to binaries and configuration files based on different platforms (e.g., Rancher, native Kubernetes, etc.).

For example:

```yaml
kubelet:
    bins:
      - kubelet
      - hyperkube kubelet
    confs:
      - /etc/kubernetes/kubelet-config.yaml
      - /var/lib/kubelet/config.yaml
```

### Commands Files Location

currently checks files location are :`https://github.com/aquasecurity/trivy-checks/tree/main/checks`

proposed command files location: `https://github.com/aquasecurity/trivy-checks/tree/main/commands`
under command file

Note: command config files will be located under `https://github.com/aquasecurity/trivy-checks/tree/main/commands` as well

### Node-collector output

The node collector will read commands and execute each command, and incorporate the output into the NodeInfo resource.

example:

```json
{
  "apiVersion": "v1",
  "kind": "NodeInfo",
  "metadata": {
    "creationTimestamp": "2023-01-04T11:37:11+02:00"
  },
  "type": "master",
  "info": {
    "adminConfFileOwnership": {
      "values": [
        "root:root"
      ]
    },
    "adminConfFilePermissions": {
      "values": [
        600
      ]
    }
    ...
  }
}
```
