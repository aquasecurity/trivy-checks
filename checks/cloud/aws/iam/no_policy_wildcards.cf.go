package iam

var cloudFormationNoPolicyWildcardsGoodExamples = []string{
	`---
Resources:
  GoodPolicy:
    Type: 'AWS::IAM::Policy'
    Properties:
      PolicyName: CFNUsers
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - 's3:ListBuckets'
            Resource: 'specific-bucket'
`,
}

var cloudFormationNoPolicyWildcardsBadExamples = []string{
	`---
Resources:
  BadPolicy:
    Type: 'AWS::IAM::Policy'
    Properties:
      PolicyName: CFNUsers
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - 'cloudformation:Describe*'
              - 'cloudformation:List*'
              - 'cloudformation:Get*'
            Resource: '*'
`,
}

var cloudFormationNoPolicyWildcardsLinks = []string{}

var cloudFormationNoPolicyWildcardsRemediationMarkdown = ``
