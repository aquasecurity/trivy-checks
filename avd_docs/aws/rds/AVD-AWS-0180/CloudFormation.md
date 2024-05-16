
Remove the public endpoint from the RDS instance.

```yaml---
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: false

```


