package redshift

var cloudFormationUseVpcGoodExamples = []string{
	`---
Resources:
  GoodCluster:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: "my-subnet-group"
`,
}

var cloudFormationUseVpcBadExamples = []string{
	`---
Resources:
  BadCluster:
    Type: AWS::Redshift::Cluster
    Properties:
      DBName: "mydb"
      ClusterType: "single-node"
`,
}

var cloudFormationUseVpcLinks = []string{}

var cloudFormationUseVpcRemediationMarkdown = ``
