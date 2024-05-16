package rds

var cloudFormationEncryptInstanceStorageDataGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"

`,
}

var cloudFormationEncryptInstanceStorageDataBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: false
`,
}

var cloudFormationEncryptInstanceStorageDataLinks = []string{}

var cloudFormationEncryptInstanceStorageDataRemediationMarkdown = ``
