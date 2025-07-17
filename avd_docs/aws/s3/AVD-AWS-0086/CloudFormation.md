
Enable blocking any PUT calls with a public ACL specified

```yaml
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
```


