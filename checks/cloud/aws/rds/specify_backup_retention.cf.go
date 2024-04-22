package rds

var cloudFormationSpecifyBackupRetentionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      BackupRetentionPeriod: 30
`,
}

var cloudFormationSpecifyBackupRetentionBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::RDS::DBInstance
    Properties:
`,
}

var cloudFormationSpecifyBackupRetentionLinks = []string{}

var cloudFormationSpecifyBackupRetentionRemediationMarkdown = ``
