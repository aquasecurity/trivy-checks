
Set a more restrictive cidr range

```yaml
AWSTemplateFormatVersion: 2010-09-09T00:00:00Z
Description: Good example of egress rule
Resources:
    BadSecurityGroup:
        Properties:
            GroupDescription: Limits security group egress traffic
            SecurityGroupEgress:
                - CidrIp: 127.0.0.1/32
                  IpProtocol: "6"
        Type: AWS::EC2::SecurityGroup

```


