
Enable server side encryption

```yaml
Resources:
    GoodFunction:
        Properties:
            SSESpecification:
                SSEEnabled: true
            TableName: GoodTable
        Type: AWS::Serverless::SimpleTable
```


