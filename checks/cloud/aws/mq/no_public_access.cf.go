package mq

var cloudFormationNoPublicAccessGoodExamples = []string{
	`---
Resources:
  GoodBroker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      PubliclyAccessible: false
`,
}

var cloudFormationNoPublicAccessBadExamples = []string{
	`---
Resources:
  BadBroker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      PubliclyAccessible: true
`,
}

var cloudFormationNoPublicAccessLinks = []string{}

var cloudFormationNoPublicAccessRemediationMarkdown = ``
