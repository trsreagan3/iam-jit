"""Stack 2 — Lambda + API Gateway.

Exercises the apigateway parser (MED-4 — restful + websocket APIs
parse to canonical action names like `apigateway:CreateRestApi`,
NOT the raw HTTP method like `apigateway:POST`).

Also exercises HIGH-3 (solo deployment MFA threshold — low-score
requests must auto-approve), HIGH-4 (response body must be valid
JSON), and MED-5 (operator tags land on the provisioned role).

We capture full plan but never actually invoke or expose anything
— plan-capture returns synthetic SDK responses; we never forward
to AWS.
"""

from __future__ import annotations

STACK_NAME = "stack_2_lambda_apigw"
STACK_TAG = "lambda-apigw"

# IAM role + Lambda + API Gateway create surface. Mix of iam, lambda,
# apigateway services so the parser+plan-capture path covers all
# three protocols (rest-json, query, REST API Gateway).
INTENDED_ACTIONS: list[dict] = [
    {
        "service": "iam",
        "operation_name": "CreateRole",
        "params": {
            "RoleName": "dogfood-stack2-lambda-exec",
            "AssumeRolePolicyDocument": (
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Allow","Principal":'
                '{"Service":"lambda.amazonaws.com"},'
                '"Action":"sts:AssumeRole"}]}'
            ),
        },
        "iam_action": "iam:CreateRole",
    },
    {
        "service": "iam",
        "operation_name": "PutRolePolicy",
        "params": {
            "RoleName": "dogfood-stack2-lambda-exec",
            "PolicyName": "logs",
            "PolicyDocument": (
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Allow","Action":'
                '["logs:CreateLogGroup","logs:CreateLogStream",'
                '"logs:PutLogEvents"],"Resource":"*"}]}'
            ),
        },
        "iam_action": "iam:PutRolePolicy",
    },
    {
        "service": "iam",
        "operation_name": "PassRole",  # synthetic — boto3 doesn't have a passrole op
        "params": {"RoleName": "dogfood-stack2-lambda-exec"},
        "iam_action": "iam:PassRole",
        "skip_plan_capture": True,  # not a real boto3 call; just a policy hint
    },
    {
        "service": "lambda",
        "operation_name": "CreateFunction",
        "params": {
            "FunctionName": "dogfood-stack2",
            "Runtime": "python3.12",
            "Role": "arn:aws:iam::000000000000:role/dogfood-stack2-lambda-exec",
            "Handler": "index.handler",
            "Code": {"ZipFile": b"def handler(e, c): return {'ok': True}\n"},
        },
        "iam_action": "lambda:CreateFunction",
    },
    {
        "service": "lambda",
        "operation_name": "AddPermission",
        "params": {
            "FunctionName": "dogfood-stack2",
            "StatementId": "allow-apigw",
            "Action": "lambda:InvokeFunction",
            "Principal": "apigateway.amazonaws.com",
        },
        "iam_action": "lambda:AddPermission",
    },
    {
        "service": "apigateway",
        "operation_name": "CreateRestApi",
        "params": {"name": "dogfood-stack2-api"},
        "iam_action": "apigateway:CreateRestApi",
    },
    {
        "service": "apigateway",
        "operation_name": "CreateResource",
        "params": {"restApiId": "abc123plan", "parentId": "root",
                   "pathPart": "hello"},
        "iam_action": "apigateway:CreateResource",
    },
    {
        "service": "apigateway",
        "operation_name": "PutMethod",
        "params": {"restApiId": "abc123plan", "resourceId": "res-plan",
                   "httpMethod": "GET", "authorizationType": "NONE"},
        "iam_action": "apigateway:PutMethod",
    },
    {
        "service": "apigateway",
        "operation_name": "PutIntegration",
        "params": {"restApiId": "abc123plan", "resourceId": "res-plan",
                   "httpMethod": "GET", "type": "AWS_PROXY",
                   "integrationHttpMethod": "POST",
                   "uri": "arn:aws:apigateway:us-east-1:lambda:path/"
                          "2015-03-31/functions/arn:aws:lambda:us-east-1:"
                          "000000000000:function:dogfood-stack2/invocations"},
        "iam_action": "apigateway:PutIntegration",
    },
    {
        "service": "apigateway",
        "operation_name": "CreateDeployment",
        "params": {"restApiId": "abc123plan", "stageName": "prod"},
        "iam_action": "apigateway:CreateDeployment",
    },
]

# Read-only accuracy probe — call a cheap iam Get that the role
# should be permitted via the included iam:GetRole grant.
ACCURACY_PROBES: list[dict] = [
    # Lambda ListFunctions is cheap, read-only, and the policy
    # we synthesize for stack 2 includes lambda:ListFunctions
    # by virtue of the policy template.
    {
        "service": "lambda",
        "operation_name": "ListFunctions",
        "params": {"MaxItems": 1},
        "iam_action": "lambda:ListFunctions",
    },
]

NEGATIVE_PROBES: list[str] = [
    "iam:ListUsers",
    "s3:CreateBucket",
]

# Stack-2-specific marker for the F14 audit assertion. The audit
# log MUST contain the canonical name `apigateway:CreateRestApi`,
# NOT the raw HTTP method `apigateway:POST`. (MED-4 regression.)
REQUIRED_AUDIT_ACTION = "apigateway:CreateRestApi"
FORBIDDEN_AUDIT_ACTION = "apigateway:POST"
