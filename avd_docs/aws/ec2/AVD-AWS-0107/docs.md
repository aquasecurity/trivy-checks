
Security groups provide stateful filtering of ingress and egress network traffic to AWS
resources. It is recommended that no security group allows unrestricted ingress access to
remote server administration ports, such as SSH to port 22 and RDP to port 3389.

### Impact
Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html


