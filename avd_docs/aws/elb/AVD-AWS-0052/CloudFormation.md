
Set drop_invalid_header_fields to true

```yaml
Resources:
  GoodExample:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      LoadBalancerAttributes:
        - Key: routing.http.drop_invalid_header_fields.enabled
          Value: true
```
```yaml
Resources:
  GoodExample:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: gateway
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html

