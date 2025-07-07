
Only use immutable images in ECR

```yaml
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      ImageTagMutability: IMMUTABLE
      RepositoryName: test-repository
```


