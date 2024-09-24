package redshift

var cloudFormationNoClassicResourcesGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of redshift sgr
Resources:
  myCluster:
    Type: "AWS::Redshift::Cluster"
    Properties:
      DBName: "mydb"
`,
}

var cloudFormationNoClassicResourcesBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift sgr
Resources:
  SecGroup:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: ""

`,
}

var cloudFormationNoClassicResourcesLinks = []string{}

var cloudFormationNoClassicResourcesRemediationMarkdown = ``
