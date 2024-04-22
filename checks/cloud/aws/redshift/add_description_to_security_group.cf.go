package redshift

var cloudFormationAddDescriptionToSecurityGroupGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: "Disallow bad stuff"
      # TODO
`,
}

var cloudFormationAddDescriptionToSecurityGroupBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: ""
      # TODO
`,
}

var cloudFormationAddDescriptionToSecurityGroupLinks = []string{}

var cloudFormationAddDescriptionToSecurityGroupRemediationMarkdown = ``
