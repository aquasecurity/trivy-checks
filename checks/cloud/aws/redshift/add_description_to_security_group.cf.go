package redshift

var cloudFormationAddDescriptionToSecurityGroupGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: "Disallow bad stuff"
`,
}

var cloudFormationAddDescriptionToSecurityGroupBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: ""
`,
}

var cloudFormationAddDescriptionToSecurityGroupLinks = []string{}

var cloudFormationAddDescriptionToSecurityGroupRemediationMarkdown = ``
