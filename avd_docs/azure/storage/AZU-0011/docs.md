
Azure Storage supports four versions of the TLS protocol: 1.0, 1.1, 1.2, and 1.3.
Azure Storage uses TLS 1.2 or TLS 1.3 on public HTTPS endpoints, while TLS 1.0 and TLS 1.1 are still supported for backward compatibility.
This check will warn if the minimum TLS version is set lower than TLS1_2. TLS1_2 and TLS1_3 are both allowed.


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version


