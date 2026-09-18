
A principal with iam:PutUserPolicy, iam:PutRolePolicy, or iam:PutGroupPolicy and a wildcard
resource can write an inline policy with admin permissions on any IAM identity, including
themselves. This enables immediate privilege escalation to full administrative access.


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://pathfinding.cloud/

- https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/


