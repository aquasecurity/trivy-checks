package msk

var cloudFormationEnableAtRestEncryptionGoodExamples = []string{
	`---
Resources:
  GoodCluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionAtRest:
          DataVolumeKMSKeyId: "foo-bar-key"
`,
}

var cloudFormationEnableAtRestEncryptionBadExamples = []string{
	`---
Resources:
  BadCluster:
    Type: AWS::MSK::Cluster
    Properties:
`,
}

var cloudFormationEnableAtRestEncryptionLinks = []string{}

var cloudFormationEnableAtRestEncryptionRemediationMarkdown = ``
