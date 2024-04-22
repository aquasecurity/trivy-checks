package sqs

var cloudFormationQueueEncryptionUsesCMKGoodExamples = []string{
	`---
Resources:
  GoodQueue:
    Type: AWS::SQS::Queue
    Properties:
      KmsMasterKeyId: some-key
      QueueName: my-queue
`,
}

var cloudFormationQueueEncryptionUsesCMKBadExamples = []string{
	`---
Resources:
  BadQueue:
    Type: AWS::SQS::Queue
    Properties:
      KmsMasterKeyId: alias/aws/sqs
      QueueName: my-queue
`,
}

var cloudFormationQueueEncryptionUsesCMKLinks = []string{}

var cloudFormationQueueEncryptionUsesCMKRemediationMarkdown = ``
