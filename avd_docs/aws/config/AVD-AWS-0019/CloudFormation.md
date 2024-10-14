
Set the aggregator to cover all regions

```yaml
Resources:
  GoodExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      AccountAggregationSources:
        - AllAwsRegions: true
      ConfigurationAggregatorName: GoodAccountLevelAggregation
```
```yaml
Resources:
  GoodExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      ConfigurationAggregatorName: GoodAccountLevelAggregation
      OrganizationAggregationSource:
        AllAwsRegions: true
```


