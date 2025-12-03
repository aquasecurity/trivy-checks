
Set a more restrictive cidr range

```yaml
AWSTemplateFormatVersion: "2010-09-09"

Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
        - CidrIp: 127.0.0.1/32
          IpProtocol: "6"
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-securitygroup.html

