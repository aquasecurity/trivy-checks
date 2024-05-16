package sns

var cloudFormationEnableTopicEncryptionGoodExamples = []string{
	`---
Resources:
  GoodTopic:
    Type: AWS::SQS::Topic
    Properties:
      TopicName: blah
      KmsMasterKeyId: some-key
`,
}

var cloudFormationEnableTopicEncryptionBadExamples = []string{
	`---
Resources:
  BadTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: blah
`,
}

var cloudFormationEnableTopicEncryptionLinks = []string{}

var cloudFormationEnableTopicEncryptionRemediationMarkdown = ``
