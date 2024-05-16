
Add descriptions for all security groups rules

```yaml---
Resources:
  GoodSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        Description: "Can connect to loopback"
        IpProtocol: "-1"

```


