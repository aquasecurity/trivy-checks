
In provider versions prior to 4:
The attribute <code>workload_metadata_config.node_metadata</code> configures how node metadata is exposed to workloads. It should be set to <code>SECURE</code> to limit metadata exposure, or <code>GKE_METADATA_SERVER</code> if Workload Identity is enabled.

Starting with provider version 4:
The attribute <code>node_metadata</code> has been removed. Instead, <code>workload_metadata_configuration.mode</code> controls node metadata exposure. When Workload Identity is enabled, it should be set to <code>GKE_METADATA</code> to prevent unnecessary exposure of the metadata API to workloads.


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#create-concealed


