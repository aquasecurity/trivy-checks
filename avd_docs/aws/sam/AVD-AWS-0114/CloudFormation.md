
Specify the exact permissions required, and to which resources they should apply instead of using wildcards.

```yaml
Resources:
  GoodFunction:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - app.lambda_handler
        EntryPoint:
          - entrypoint1
        WorkingDirectory: workDir
      Policies:
        - AWSLambdaExecute
        - Version: "2012-10-17"
          Statement:
            - Effect: Allow
              Action:
                - s3:GetObject
                - s3:GetObjectACL
              Resource: arn:aws:s3:::my-bucket/*
```


