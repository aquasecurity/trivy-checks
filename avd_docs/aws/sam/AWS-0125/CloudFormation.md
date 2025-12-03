
Enable tracing

```yaml
Resources:
  GoodFunction:
    Type: AWS::Serverless::Function
    Properties:
      ImageConfig:
        Command:
          - app.lambda_handler
        EntryPoint:
          - entrypoint1
        WorkingDirectory: workDir
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      PackageType: Image
      Tracing: Active
```


