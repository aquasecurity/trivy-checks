
Set a more restrictive CIDR range

```yaml
AWSTemplateFormatVersion: "2010-09-09"

Description: Godd example of excessive ports

Resources:
  NetworkACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
      VpcId: something

  Rule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
      CidrBlock: 10.0.0.0/8
      NetworkAclId: !Ref NetworkACL
      Protocol: 6
      RuleAction: allow
      PortRange:
        From: 22
        To: 22
```


