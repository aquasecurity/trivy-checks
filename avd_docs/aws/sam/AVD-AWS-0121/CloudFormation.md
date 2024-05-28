
Enable server side encryption

```yaml---
Resources:
  GoodFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: GoodTable
      SSESpecification:
        SSEEnabled: true

```


