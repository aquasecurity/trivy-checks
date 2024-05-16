package rds

var cloudFormationNoPublicDbAccessGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: false
`,
}

var cloudFormationNoPublicDbAccessBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
`,
}

var cloudFormationNoPublicDbAccessLinks = []string{}

var cloudFormationNoPublicDbAccessRemediationMarkdown = ``
