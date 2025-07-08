
Restrict public access to the S3 bucket

```yaml
Resources:
  GoodExampleBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
      BucketName: my-bucket

  GoodExampleTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      S3BucketName: my-bucket
      TrailName: Cloudtrail
```


