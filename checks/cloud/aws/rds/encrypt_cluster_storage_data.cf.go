package rds

var cloudFormationEncryptClusterStorageDataGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::RDS::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"
`,
}

var cloudFormationEncryptClusterStorageDataBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::RDS::DBCluster
    Properties:
      StorageEncrypted: false
`,
}

var cloudFormationEncryptClusterStorageDataLinks = []string{}

var cloudFormationEncryptClusterStorageDataRemediationMarkdown = ``
