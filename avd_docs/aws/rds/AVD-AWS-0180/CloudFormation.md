
Remove the public endpoint from the RDS instance.

```yaml
Resources:
  GoodExample:
    Properties:
      PubliclyAccessible: false
    Type: AWS::RDS::DBInstance

```


