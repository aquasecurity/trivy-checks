package ec2

var cloudFormationAddDescriptionToSecurityGroupGoodExamples = []string{
	`---
Resources:
  GoodSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "-1"
`,
}

var cloudFormationAddDescriptionToSecurityGroupBadExamples = []string{
	`---
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "-1"
`,
}

var cloudFormationAddDescriptionToSecurityGroupLinks = []string{}

var cloudFormationAddDescriptionToSecurityGroupRemediationMarkdown = ``
