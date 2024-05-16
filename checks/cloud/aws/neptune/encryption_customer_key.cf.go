package neptune

var cloudFormationCheckEncryptionCustomerKeyGoodExamples = []string{
	`---
Resources:
  GoodCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"
`,
}

var cloudFormationCheckEncryptionCustomerKeyBadExamples = []string{
	`---
Resources:
  BadCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      StorageEncrypted: false
`,
}

var cloudFormationCheckEncryptionCustomerKeyLinks = []string{}

var cloudFormationCheckEncryptionCustomerKeyRemediationMarkdown = ``
