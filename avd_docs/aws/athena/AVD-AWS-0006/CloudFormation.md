
Enable encryption at rest for Athena databases and workgroup configurations

```yaml
Resources:
  GoodExample:
    Type: AWS::Athena::WorkGroup
    Properties:
      Name: goodExample
      WorkGroupConfiguration:
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
```


