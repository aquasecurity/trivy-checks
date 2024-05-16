package mq

var cloudFormationEnableAuditLoggingGoodExamples = []string{
	`---
Resources:
  GoodBroker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        Audit: true
`,
}

var cloudFormationEnableAuditLoggingBadExamples = []string{
	`---
Resources:
  BadBroker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        Audit: false
`,
}

var cloudFormationEnableAuditLoggingLinks = []string{}

var cloudFormationEnableAuditLoggingRemediationMarkdown = ``
