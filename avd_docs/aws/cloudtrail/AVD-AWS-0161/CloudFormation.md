
Restrict public access to the S3 bucket

```yaml
Resources:
  GoodExampleBucket:
    Properties:
      AccessControl: Private
      BucketName: my-bucket
    Type: AWS::S3::Bucket
  GoodExampleTrail:
    Properties:
      IsLogging: true
      S3BucketName: my-bucket
      TrailName: Cloudtrail
    Type: AWS::CloudTrail::Trail

```


