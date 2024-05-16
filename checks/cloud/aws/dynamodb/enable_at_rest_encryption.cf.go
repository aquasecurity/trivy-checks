package dynamodb

var cloudFormationEnableAtRestEncryptionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::DAX::Cluster
    Properties:
      ClusterName: "MyDAXCluster"
      NodeType: "dax.r3.large"
      ReplicationFactor: 1
      IAMRoleARN: "arn:aws:iam::111122223333:role/DaxAccess"
      Description: "DAX cluster with encryption at rest"
      SSESpecification:
        SSEEnabled: true
`,
}

var cloudFormationEnableAtRestEncryptionBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::DAX::Cluster
    Properties:
      ClusterName: "MyDAXCluster"
      NodeType: "dax.r3.large"
      ReplicationFactor: 1
      IAMRoleARN: "arn:aws:iam::111122223333:role/DaxAccess"
      Description: "DAX cluster without encryption at rest"
      SubnetGroupName: !Ref subnetGroupClu
`,
}

var cloudFormationEnableAtRestEncryptionLinks = []string{}

var cloudFormationEnableAtRestEncryptionRemediationMarkdown = ``
