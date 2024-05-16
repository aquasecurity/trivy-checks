package rds

var cloudFormationPerformanceInsightsEncryptionCustomerKeyGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: "something"
`,
}

var cloudFormationPerformanceInsightsEncryptionCustomerKeyBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
`,
}

var cloudFormationPerformanceInsightsEncryptionCustomerKeyLinks = []string{}

var cloudFormationPerformanceInsightsEncryptionCustomerKeyRemediationMarkdown = ``
