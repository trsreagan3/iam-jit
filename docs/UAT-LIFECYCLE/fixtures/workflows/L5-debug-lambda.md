# L5 fixture — "debug a Lambda function" workflow

Realistic shape of AWS API calls + HTTPS calls an agent makes when
asked to debug a Lambda. Used by L5 to drive synthetic activity.

## Activity script (run via deterministic-harness.sh)

### ibounce-facing (AWS)

```
GET  iam:GetRole              role=arn:aws:iam::000000000000:role/lambda-exec
GET  lambda:GetFunction       fn=demo-fn
GET  lambda:GetFunctionConfiguration  fn=demo-fn
GET  logs:DescribeLogGroups   prefix=/aws/lambda/demo-fn
GET  logs:GetLogEvents        group=/aws/lambda/demo-fn limit=100
GET  cloudwatch:GetMetricStatistics  fn=demo-fn metric=Errors
GET  s3:GetObject             bucket=lambda-deployments key=demo-fn.zip
GET  ec2:DescribeVpcs
GET  ec2:DescribeSubnets
GET  ec2:DescribeSecurityGroups
```

### gbounce-facing (HTTPS)

```
GET https://docs.aws.amazon.com/lambda/latest/dg/...
GET https://docs.python.org/3/library/...
GET https://stackoverflow.com/questions/tagged/aws-lambda
```

Expected generated profile from `bounce_profile_generate_from_audit`:

* ibounce: read-only on lambda + logs + cloudwatch + s3:GetObject
  on the deployments bucket only.
* gbounce: allow docs.aws.amazon.com + docs.python.org +
  stackoverflow.com.

Adversarial check (Phase 3 enforce mode): `kms:Decrypt` should be
DENIED (not in the generated profile).
