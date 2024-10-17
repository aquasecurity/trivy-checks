
Set a more restrictive CIDR range

```yaml
Resources:
  GoodSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupIngress:
        - CidrIp: 127.0.0.1/32
          IpProtocol: "6"
```


