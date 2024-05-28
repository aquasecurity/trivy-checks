
Use customer managed keys

```yaml---
Resources:
  GoodSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: "secret"
      KmsKeyId: "my-key-id"
      Name: "blah"
      SecretString: "don't tell anyone"

```


