
Enable tracing

```yaml
Resources:
  GoodExample:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Handler: index.handler
      Runtime: nodejs12.x
      TracingConfig:
        Mode: Active
```


