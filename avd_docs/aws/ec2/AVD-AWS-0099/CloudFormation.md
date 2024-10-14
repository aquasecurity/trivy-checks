
Add descriptions for all security groups

```yaml
Resources:
    GoodSecurityGroup:
        Properties:
            GroupDescription: Limits security group egress traffic
            SecurityGroupEgress:
                - CidrIp: 127.0.0.1/32
                  IpProtocol: "-1"
        Type: AWS::EC2::SecurityGroup
```


