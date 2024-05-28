package mq

var cloudFormationEnableGeneralLoggingGoodExamples = []string{
	`---
Resources:
  GoodBroker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        General: true
`,
}

var cloudFormationEnableGeneralLoggingBadExamples = []string{
	`---
Resources:
  BadBroker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        General: false
`,
}

var cloudFormationEnableGeneralLoggingLinks = []string{}

var cloudFormationEnableGeneralLoggingRemediationMarkdown = ``
