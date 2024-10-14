
Set specific allowed ports

```yaml
AWSTemplateFormatVersion: 2010-09-09T00:00:00Z
Description: Good example of excessive ports
Resources:
    NetworkACL:
        Properties:
            RuleAction: allow
            VpcId: something
        Type: AWS::EC2::NetworkAcl
    Rule:
        Properties:
            NetworkAclId: null
            Protocol: 6
            Ref: NetworkACL
            RuleAction: allow
        Type: AWS::EC2::NetworkAclEntry
```


