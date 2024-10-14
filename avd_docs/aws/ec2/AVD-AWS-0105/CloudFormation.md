
Set a more restrictive CIDR range

```yaml
AWSTemplateFormatVersion: 2010-09-09T00:00:00Z
Description: Godd example of excessive ports
Resources:
    NetworkACL:
        Properties:
            VpcId: something
        Type: AWS::EC2::NetworkAcl
    Rule:
        Properties:
            CidrBlock: 10.0.0.0/8
            NetworkAclId:
                Ref: NetworkACL
            Protocol: 6
            RuleAction: allow
        Type: AWS::EC2::NetworkAclEntry
```


