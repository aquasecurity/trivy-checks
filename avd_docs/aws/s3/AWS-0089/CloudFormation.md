
Add a logging block to the resource to enable access logging

```yaml
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      LoggingConfiguration:
        DestinationBucketName: !Ref TestLoggingBucket
        LogFilePrefix: accesslogs/

  TestLoggingBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: LogDeliveryWrite
```


