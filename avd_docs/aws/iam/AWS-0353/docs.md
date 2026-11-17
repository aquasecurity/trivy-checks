
A principal with iam:DeleteUserPermissionsBoundary or iam:DeleteRolePermissionsBoundary
can remove permissions boundaries that act as guardrails on IAM identities. Once boundaries
are removed, the identity's full unconstrained permissions become active, which may include
administrative access that was previously limited by the boundary.


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://pathfinding.cloud/

- https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/


