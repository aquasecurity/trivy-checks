package rds

var cloudFormationEnablePerformanceInsightsGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: "something"

`,
}

var cloudFormationEnablePerformanceInsightsBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: false
`,
}

var cloudFormationEnablePerformanceInsightsLinks = []string{}

var cloudFormationEnablePerformanceInsightsRemediationMarkdown = ``
