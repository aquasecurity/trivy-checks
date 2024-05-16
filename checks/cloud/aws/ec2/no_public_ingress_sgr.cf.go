package ec2

var cloudFormationNoPublicIngressSgrGoodExamples = []string{
	`---
Resources:
  GoodSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupIngress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "6"
`,
}

var cloudFormationNoPublicIngressSgrBadExamples = []string{
	`---
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupIngress:
      - CidrIp: 0.0.0.0/0
        IpProtocol: "6"
`,
}

var cloudFormationNoPublicIngressSgrLinks = []string{}

var cloudFormationNoPublicIngressSgrRemediationMarkdown = ``
