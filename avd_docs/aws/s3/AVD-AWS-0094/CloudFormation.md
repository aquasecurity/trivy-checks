
Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies

```yaml
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
```


