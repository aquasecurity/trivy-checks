package sqs

var cloudFormationEnableQueueEncryptionGoodExamples = []string{
	`---
Resources:
  GoodQueue:
    Type: AWS::SQS::Queue
    Properties:
      KmsMasterKeyId: some-key
      QueueName: my-queue
`,
}

var cloudFormationEnableQueueEncryptionBadExamples = []string{
	`---
Resources:
  BadQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: my-queue
`,
}

var cloudFormationEnableQueueEncryptionLinks = []string{}

var cloudFormationEnableQueueEncryptionRemediationMarkdown = ``
