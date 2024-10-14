
Add descriptions for all security groups

```yaml
Resources:
  GoodSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
        - CidrIp: 127.0.0.1/32
          IpProtocol: "-1"
```


