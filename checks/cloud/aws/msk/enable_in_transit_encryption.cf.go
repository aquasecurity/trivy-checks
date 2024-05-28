package msk

var cloudFormationEnableInTransitEncryptionGoodExamples = []string{
	`---
Resources:
  GoodCluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionInTransit:
          ClientBroker: "TLS"
`,
}

var cloudFormationEnableInTransitEncryptionBadExamples = []string{
	`---
Resources:
  BadCluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionInTransit:
          ClientBroker: "TLS_PLAINTEXT"

`,
}

var cloudFormationEnableInTransitEncryptionLinks = []string{}

var cloudFormationEnableInTransitEncryptionRemediationMarkdown = ``
