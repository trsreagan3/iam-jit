# L5 fixture — "terraform plan" workflow

A second realistic shape for L5; gives the agent two distinct
profile-generation patterns to compare.

## Activity script

### ibounce-facing (AWS read-only describe pattern)

```
GET ec2:DescribeInstances
GET ec2:DescribeVolumes
GET ec2:DescribeSecurityGroups
GET vpc:DescribeVpcs
GET rds:DescribeDBInstances
GET iam:GetRole          role=arn:aws:iam::000000000000:role/terraform-exec
GET iam:GetPolicy        policy=arn:aws:iam::000000000000:policy/terraform-policy
GET s3:GetObject         bucket=tf-state key=prod/terraform.tfstate
GET s3:HeadObject        bucket=tf-state key=prod/terraform.tfstate
GET dynamodb:GetItem     table=tf-state-lock LockID=...
```

### gbounce-facing (HTTPS)

```
GET https://registry.terraform.io/...
GET https://releases.hashicorp.com/terraform-provider-aws/...
```

Expected profile: AWS describe-* family + s3:Get on tf-state bucket
+ dynamodb:GetItem on the lock table; gbounce allows registry +
releases hosts.

Adversarial check: `s3:DeleteObject` should be DENIED (terraform
plan is read-only; apply would need a different profile).
