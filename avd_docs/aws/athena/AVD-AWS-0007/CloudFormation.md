
Enforce the configuration to prevent client overrides

```yaml
Resources:
  GoodExample:
    Type: AWS::Athena::WorkGroup
    Properties:
      Name: goodExample
      WorkGroupConfiguration:
        EnforceWorkGroupConfiguration: true
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
```


