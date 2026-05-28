"""Stack 1 — VPC + EC2.

Exercises the XML-protocol services. EC2 still speaks query/XML so
this is where HIGH-1 (plan-capture XML-envelope) regressions show
up first. We deliberately enumerate the full create-vpc / subnet /
igw / route-table / sg / run-instances surface even though we never
actually run an instance (plan-capture never forwards to AWS).

Per the spec, ALL actions are recorded as INTENDED_ACTIONS but only
the read-only Describes show up in ACCURACY_PROBES — we want the
ROLE to be over-broad enough to allow them but we don't actually
want to spend money creating real EC2 state in CI.
"""

from __future__ import annotations

STACK_NAME = "stack_1_vpc_ec2"
STACK_TAG = "vpc-ec2"

# Plan-capture intent. The plan-capture proxy returns SDK-shaped
# synthetic success for every entry; nothing forwards to AWS so
# these CAN reference resources that don't exist.
INTENDED_ACTIONS: list[dict] = [
    {
        "service": "ec2",
        "operation_name": "DescribeAvailabilityZones",
        "params": {},
        "iam_action": "ec2:DescribeAvailabilityZones",
    },
    {
        "service": "ec2",
        "operation_name": "DescribeImages",
        "params": {"Owners": ["amazon"], "MaxResults": 5,
                   "Filters": [{"Name": "name",
                                "Values": ["amzn2-ami-hvm-2.0*"]}]},
        "iam_action": "ec2:DescribeImages",
    },
    {
        "service": "ec2",
        "operation_name": "CreateVpc",
        "params": {"CidrBlock": "10.42.0.0/16"},
        "iam_action": "ec2:CreateVpc",
    },
    {
        "service": "ec2",
        "operation_name": "CreateSubnet",
        "params": {"VpcId": "vpc-0plan", "CidrBlock": "10.42.1.0/24"},
        "iam_action": "ec2:CreateSubnet",
    },
    {
        "service": "ec2",
        "operation_name": "CreateInternetGateway",
        "params": {},
        "iam_action": "ec2:CreateInternetGateway",
    },
    {
        "service": "ec2",
        "operation_name": "AttachInternetGateway",
        "params": {"InternetGatewayId": "igw-0plan", "VpcId": "vpc-0plan"},
        "iam_action": "ec2:AttachInternetGateway",
    },
    {
        "service": "ec2",
        "operation_name": "CreateRouteTable",
        "params": {"VpcId": "vpc-0plan"},
        "iam_action": "ec2:CreateRouteTable",
    },
    {
        "service": "ec2",
        "operation_name": "CreateRoute",
        "params": {"RouteTableId": "rtb-0plan",
                   "DestinationCidrBlock": "0.0.0.0/0",
                   "GatewayId": "igw-0plan"},
        "iam_action": "ec2:CreateRoute",
    },
    {
        "service": "ec2",
        "operation_name": "AssociateRouteTable",
        "params": {"RouteTableId": "rtb-0plan", "SubnetId": "subnet-0plan"},
        "iam_action": "ec2:AssociateRouteTable",
    },
    {
        "service": "ec2",
        "operation_name": "CreateSecurityGroup",
        "params": {"VpcId": "vpc-0plan", "GroupName": "dogfood",
                   "Description": "dogfood"},
        "iam_action": "ec2:CreateSecurityGroup",
    },
    {
        "service": "ec2",
        "operation_name": "AuthorizeSecurityGroupIngress",
        "params": {"GroupId": "sg-0plan", "IpProtocol": "tcp",
                   "FromPort": 22, "ToPort": 22,
                   "CidrIp": "10.42.0.0/16"},
        "iam_action": "ec2:AuthorizeSecurityGroupIngress",
    },
    {
        "service": "ec2",
        "operation_name": "RunInstances",
        "params": {"ImageId": "ami-0plan", "InstanceType": "t3.nano",
                   "MinCount": 1, "MaxCount": 1,
                   "SubnetId": "subnet-0plan",
                   "SecurityGroupIds": ["sg-0plan"]},
        "iam_action": "ec2:RunInstances",
    },
    {
        "service": "ec2",
        "operation_name": "DescribeInstances",
        "params": {"InstanceIds": ["i-0plan"]},
        "iam_action": "ec2:DescribeInstances",
    },
]

# Read-only Describes the assumed role MUST be able to perform
# against REAL AWS. Limit to genuinely cheap, no-state-change
# operations.
ACCURACY_PROBES: list[dict] = [
    {
        "service": "ec2",
        "operation_name": "DescribeAvailabilityZones",
        "params": {},
        "iam_action": "ec2:DescribeAvailabilityZones",
    },
]

# Out-of-scope: actions NOT in INTENDED_ACTIONS. The assumed role
# MUST return AccessDenied for these.
NEGATIVE_PROBES: list[str] = [
    "iam:ListUsers",
    "s3:ListAllMyBuckets",
]
