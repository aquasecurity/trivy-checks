
Enable logging for ElasticSearch domains

```yaml
Resources:
  GoodExample:
    Type: AWS::OpenSearchService::Domain
    Properties:
      LogPublishingOptions:
        AUDIT_LOGS:
          CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:/aws/opensearch/domains/opensearch-application-logs
          Enabled: true
```
```yaml
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      LogPublishingOptions:
        AUDIT_LOGS:
          CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:/aws/opensearch/domains/opensearch-application-logs
          Enabled: true
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html

 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html

