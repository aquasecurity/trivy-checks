
Enable cache encryption

```yaml
Resources:
  GoodExample:
    Type: AWS::Serverless::Api
    Properties:
      MethodSettings:
        CacheDataEncrypted: true
      Name: Good SAM API example
      StageName: Prod
```


