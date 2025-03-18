
Enable ElasticSearch domain encryption

```yaml
Resources:
  GoodExample:
    Type: AWS::OpenSearchService::Domain
    Properties:
      EncryptionAtRestOptions:
        Enabled: true
```
```yaml
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      EncryptionAtRestOptions:
        Enabled: true
```


