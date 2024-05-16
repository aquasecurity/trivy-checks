package redshift

var cloudFormationEncryptionCustomerKeyGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Redshift::Cluster
    Properties:
      Encrypted: true
      KmsKeyId: "something"
`,
}

var cloudFormationEncryptionCustomerKeyBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Redshift::Cluster
    Properties:
      Encrypted: false
`,
}

var cloudFormationEncryptionCustomerKeyLinks = []string{}

var cloudFormationEncryptionCustomerKeyRemediationMarkdown = ``
