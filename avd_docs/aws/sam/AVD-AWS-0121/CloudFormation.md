
Enable server side encryption

```yaml
Resources:
  GoodFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      SSESpecification:
        SSEEnabled: true
      TableName: GoodTable
```


