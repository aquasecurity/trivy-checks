package msk

var cloudFormationEnableLoggingGoodExamples = []string{
	`---
Resources:
  GoodCluster:
    Type: AWS::MSK::Cluster
    Properties:
      LoggingInfo:
        BrokerLogs:
          S3:
            Enabled: true


`,
}

var cloudFormationEnableLoggingBadExamples = []string{
	`---
Resources:
  BadCluster:
    Type: AWS::MSK::Cluster
    Properties:
      LoggingInfo:
        BrokerLogs:
          CloudWatchLogs:
            Enabled: false
`,
}

var cloudFormationEnableLoggingLinks = []string{}

var cloudFormationEnableLoggingRemediationMarkdown = ``
