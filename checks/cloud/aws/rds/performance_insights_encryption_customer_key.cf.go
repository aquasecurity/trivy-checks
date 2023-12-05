package rds

var cloudFormationPerformanceInsightsEncryptionCustomerKeyGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: "something"

`,
}

var cloudFormationPerformanceInsightsEncryptionCustomerKeyBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true

`,
}

var cloudFormationPerformanceInsightsEncryptionCustomerKeyLinks = []string{}

var cloudFormationPerformanceInsightsEncryptionCustomerKeyRemediationMarkdown = ``
