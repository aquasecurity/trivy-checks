package rds

var cloudFormationNoClassicResourcesGoodExamples = []string{
	`---
Resources:
# TODO
`,
}

var cloudFormationNoClassicResourcesBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::RDS::DBSecurityGroup
    Properties:
      Description: ""
      # TODO
`,
}

var cloudFormationNoClassicResourcesLinks = []string{}

var cloudFormationNoClassicResourcesRemediationMarkdown = ``
