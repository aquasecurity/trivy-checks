
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
          FromPort: 22
          ToPort: 22
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-securitygroup.html

