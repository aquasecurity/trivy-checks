
A principal with iam:UpdateAssumeRolePolicy and a wildcard resource can rewrite the trust
policy of any IAM role to allow self-assumption. This enables lateral movement to any role
in the account, including administrative roles, effectively granting full account compromise.


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://pathfinding.cloud/

- https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/


