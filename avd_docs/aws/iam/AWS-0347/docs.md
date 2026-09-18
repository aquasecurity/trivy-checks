
A principal with iam:CreatePolicyVersion can create a new version of an IAM policy with
unrestricted permissions (e.g., *:*) and set it as the default version. This effectively
grants the principal full administrative access, bypassing the original policy restrictions.
This is a well-known privilege escalation vector in AWS environments.


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://pathfinding.cloud/

- https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/


