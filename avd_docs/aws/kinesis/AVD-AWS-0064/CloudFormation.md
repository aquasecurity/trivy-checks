
Enable in transit encryption

```yaml
Resources:
  GoodExample:
    Properties:
      Name: GoodExample
      RetentionPeriodHours: 168
      ShardCount: 3
      StreamEncryption:
        EncryptionType: KMS
        KeyId: alis/key
      Tags:
        - Key: Environment
          Value: Production
    Type: AWS::Kinesis::Stream

```


