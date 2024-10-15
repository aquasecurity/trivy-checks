
Enable access logging on the bucket

```yaml
Resources:
  GoodExampleBucket:
    Properties:
      BucketName: my-bucket
      LoggingConfiguration:
        DestinationBucketName: logging-bucket
        LogFilePrefix: accesslogs/
    Type: AWS::S3::Bucket
  GoodExampleTrail:
    Properties:
      IsLogging: true
      S3BucketName: my-bucket
      TrailName: Cloudtrail
    Type: AWS::CloudTrail::Trail

```


