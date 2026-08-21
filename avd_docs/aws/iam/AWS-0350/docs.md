
A principal with iam:PassRole and ec2:RunInstances can launch an EC2 instance with a
privileged instance profile attached. By accessing the instance metadata service (IMDS),
the attacker can steal the role credentials and escalate privileges.


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://pathfinding.cloud/

- https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/


