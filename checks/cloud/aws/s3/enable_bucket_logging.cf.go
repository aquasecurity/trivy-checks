package s3

var cloudFormationEnableBucketLoggingGoodExamples = []string{
	`---
Resources:
  TestBucket:
    Type: AWS::S3::Bucket
    Properties:
      LoggingConfiguration:
        DestinationBucketName: !Ref TestLoggingBucket
        LogFilePrefix: accesslogs/

  TestLoggingBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: LogDeliveryWrite
`,
}

var cloudFormationEnableBucketLoggingBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableBucketLoggingLinks = []string{}

var cloudFormationEnableBucketLoggingRemediationMarkdown = ``
