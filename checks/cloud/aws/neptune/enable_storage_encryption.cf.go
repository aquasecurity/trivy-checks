package neptune

var cloudFormationEnableStorageEncryptionGoodExamples = []string{
	`---
Resources:
  GoodCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"
`,
}

var cloudFormationEnableStorageEncryptionBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  BadCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      StorageEncrypted: false
`,
}

var cloudFormationEnableStorageEncryptionLinks = []string{}

var cloudFormationEnableStorageEncryptionRemediationMarkdown = ``
