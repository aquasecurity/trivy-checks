package sns

var cloudFormationTopicEncryptionUsesCMKGoodExamples = []string{
	`---
Resources:
  GoodTopic:
    Type: AWS::SQS::Topic
    Properties:
      TopicName: blah
      KmsMasterKeyId: some-key
`,
}

var cloudFormationTopicEncryptionUsesCMKBadExamples = []string{
	`---
Resources:
  BadTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: blah
      KmsMasterKeyId: alias/aws/sns
`,
}

var cloudFormationTopicEncryptionUsesCMKLinks = []string{}

var cloudFormationTopicEncryptionUsesCMKRemediationMarkdown = ``
