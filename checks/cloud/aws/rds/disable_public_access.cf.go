package rds

var cloudFormationNoPublicDbAccessGoodExamples = []string{
	`---
Resources:
  GoodQueue:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: false
`,
}

var cloudFormationNoPublicDbAccessBadExamples = []string{
	`---
Resources:
  BadQueue:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
`,
}

var cloudFormationNoPublicDbAccessLinks = []string{}

var cloudFormationNoPublicDbAccessRemediationMarkdown = ``
