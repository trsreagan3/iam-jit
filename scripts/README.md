# scripts/

Operator-side helper scripts. Most are calibration / corpus tooling — see
each script's docstring. This README documents the AWS-usage builder, which
is the only script that runs on an unattended schedule.

---

## `aws_usage_builder.py` — daily AWS-usage cron

### What this is

A tiny daily cron job that makes three cheap AWS API calls against the
operator's own AWS account:

1. `s3:PutObject` — one 1-byte file per day at
   `s3://$IAM_JIT_USAGE_BUCKET/usage-builder/YYYY-MM-DD.txt`
2. `cloudwatch:PutMetricData` — namespace `iam-jit/usage-builder`,
   metric `daily_tick`, value `1`
3. `ec2:DescribeRegions` — read-only; free; counts as usage

Each run writes one structured line per call to
`~/.iam-jit/aws-usage-builder.log`.

### Why this exists

Amazon's 2026-05-19 Bedrock denial email says, verbatim:

> Continue to actively use other AWS services on your account to build
> Usage and billing history.

The re-application window opens 30 days after denial. This script
guarantees daily usage across three distinct AWS service categories
(storage, monitoring, compute) without manual effort. Total spend at
default cadence: well under $1 / month.

### Setup

#### 1. Create a private bucket you own

```sh
aws s3api create-bucket --bucket my-usage-builder-bucket --region us-east-1
```

Strongly recommended: attach an S3 lifecycle rule that expires objects
under `usage-builder/` after 90 days. The script never deletes objects.

#### 2. Create a least-privilege IAM principal

Attach a policy that grants only:

- `s3:PutObject` on `arn:aws:s3:::my-usage-builder-bucket/usage-builder/*`
- `cloudwatch:PutMetricData` (cannot be resource-scoped — scope via
  `cloudwatch:namespace` condition key set to `iam-jit/usage-builder`)
- `ec2:DescribeRegions` on `*` (the only resource it accepts)

```sh
aws configure --profile iam-jit-usage
```

#### 3. Export the bucket name and install the cron entry

```sh
export IAM_JIT_USAGE_BUCKET=my-usage-builder-bucket
export AWS_PROFILE=iam-jit-usage

# Edit the crontab template first — set absolute paths + the bucket name
$EDITOR scripts/aws_usage_builder.crontab.example

# Install (appends to any existing crontab)
(crontab -l 2>/dev/null; cat scripts/aws_usage_builder.crontab.example) | crontab -
```

#### 4. Smoke-test it once interactively

```sh
IAM_JIT_USAGE_BUCKET=my-usage-builder-bucket \
AWS_PROFILE=iam-jit-usage \
python3 scripts/aws_usage_builder.py
```

You should see three `OK` lines + one `summary ok=3/3` line, both on
stdout and appended to `~/.iam-jit/aws-usage-builder.log`.

### Verify it's running

```sh
# Most recent ticks (one line per AWS call)
tail ~/.iam-jit/aws-usage-builder.log

# Cron-side output (in case the script itself failed to launch)
tail /tmp/aws-usage-builder.cron.log

# AWS-side proof: bucket should have one object per day
aws s3 ls "s3://$IAM_JIT_USAGE_BUCKET/usage-builder/"

# AWS-side proof: CloudWatch metric should show one data point per day
aws cloudwatch get-metric-statistics \
    --namespace iam-jit/usage-builder \
    --metric-name daily_tick \
    --start-time "$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')" \
    --end-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --period 86400 \
    --statistics Sum
```

### AWS-billing console

Confirm usage is actually accruing:

> <https://console.aws.amazon.com/billing/home#/bills>

Look for non-zero entries under the S3, CloudWatch, and EC2 service rows.

### Day-30 reminder

Once 30 days of green logs are in the bag, re-apply for Bedrock model
access:

> <https://console.aws.amazon.com/bedrock/>

### Behavior on failure

- Missing credentials → clean error, exit code `4`, no AWS calls attempted
- Missing `IAM_JIT_USAGE_BUCKET` → clean error, exit code `2`
- A single call failing → other two still run; exit code `0`
- All three calls failing → exit code `1` (cron emails operator)

### Cost estimate

At one tick per day:

| Service     | Per-day usage             | Monthly                 |
|-------------|---------------------------|-------------------------|
| S3          | 1 PUT + 1 byte stored     | ~30 PUTs ($0.00015) + ~30 bytes (free tier) |
| CloudWatch  | 1 PutMetricData call      | 30 calls (well under free-tier 1M / month)  |
| EC2         | 1 DescribeRegions call    | 30 calls (free)         |

Total: **well under $1 / month**, dominated by S3 request pricing.

### Constraints honored

- `[[creates-never-mutates]]` — read-only on the operator's machine
  outside the log file + the 1-byte S3 object.
- `[[self-host-zero-billing-dependency]]` — talks only to the operator's
  own AWS account; no phone-home.
- `[[don't-tailor-to-lighthouse]]` — generic account-warming helper; no
  hardcoded account IDs.
- `[[push-policy-public-repo]]` — diff is scanned before push.
