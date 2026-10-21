
A principal with iam:PassRole, lambda:CreateFunction, and lambda:InvokeFunction can create
a Lambda function with an administrative role attached, invoke it, and steal the role's
credentials. This combination of permissions enables a well-known privilege escalation path
through AWS Lambda.


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://pathfinding.cloud/

- https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/


