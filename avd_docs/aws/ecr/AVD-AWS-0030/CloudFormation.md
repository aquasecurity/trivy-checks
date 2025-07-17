
Enable ECR image scanning

```yaml
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      ImageScanningConfiguration:
        ScanOnPush: true
      RepositoryName: test-repository
```


