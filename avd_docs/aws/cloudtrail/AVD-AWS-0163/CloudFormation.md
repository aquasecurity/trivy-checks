
Enable access logging on the bucket

```yaml
Resources:
  GoodExampleBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
      LoggingConfiguration:
        DestinationBucketName: logging-bucket
        LogFilePrefix: accesslogs/

  GoodExampleTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      S3BucketName: my-bucket
      TrailName: Cloudtrail
```


