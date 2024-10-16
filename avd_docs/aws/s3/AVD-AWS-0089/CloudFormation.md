
Add a logging block to the resource to enable access logging

```yaml
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      LoggingConfiguration:
        DestinationBucketName: logging-bucket
        LogFilePrefix: accesslogs/
```
```yaml
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
      BucketName: my-s3-bucket-${BucketSuffix}
      LoggingConfiguration:
        DestinationBucketName:
          - EnvironmentMapping
          - s3
          - logging
        LogFilePrefix: s3-logs/AWSLogs/${AWS::AccountId}/my-s3-bucket-${BucketSuffix}
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
```


