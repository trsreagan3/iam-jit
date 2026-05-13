# IAM Risk & Bypass Research Compendium
_Compiled 2026-05-13 for the iam-risk-score adversarial test corpus._

This document catalogs publicly-known IAM risk patterns, privilege-escalation paths, and policy-bypass techniques sourced from offensive-security research (Rhino Security Labs, Bishop Fox, NCC Group, Datadog Security Labs, Wiz Research, Sysdig, Palo Alto Unit 42, etc.), AWS's own documentation, and post-mortems of real-world breaches. Every claim is cited. The document is intended to seed adversarial test fixtures for an IAM policy risk scorer — not to provide exploit code.

Sections:

1. Known IAM privilege-escalation paths (PMapper + Rhino + HackingTheCloud)
2. Pacu framework abuse modules
3. CloudGoat intentionally-vulnerable scenarios
4. Resource-based policy abuse patterns
5. Real-world incident root causes
6. CloudSplaining risk categories
7. AWS IAM Access Analyzer finding taxonomy
8. MITRE ATT&CK cloud-IaaS mapping
9. Newer-service and emerging attack surface (2023-2026)
10. JSON / parser / grammar bypass techniques
11. Condition-key bypass techniques
12. NotAction / NotResource / NotPrincipal anti-patterns
13. Service-aliasing & action-naming edge cases

---

## Section 1: Known Privilege Escalation Paths

The canonical list combines Rhino Security Labs' 21 + 7 follow-ups (Spencer Gietzen 2018-2020), Bishop Fox's IAM Vulnerable additions (31 paths), NCC Group PMapper's 10 service-specific edges, HackingTheCloud's continuously updated catalog (40+ paths), and Datadog Pathfinding.cloud's expansion. Sources: [Rhino blog part 1](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/), [Rhino blog part 2](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/), [Rhino central repo](https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation), [HackingTheCloud IAM privesc](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/), [Pathfinding.cloud](https://github.com/DataDog/pathfinding.cloud).

### 1.1 CreatePolicyVersion (default-flag abuse)
- **Required actions:** `iam:CreatePolicyVersion`
- **Resource scope needed:** any managed policy attached to the attacker's principal
- **Mechanism:** Create a new version of an attached managed policy with `--set-as-default`. The `--set-as-default` flag is implicit in `CreatePolicyVersion` and does NOT require the separate `iam:SetDefaultPolicyVersion` permission. The new version can grant `Action:*` on `Resource:*`.
- **Source:** Rhino #1
- **Detection notes:** flag any policy whose attached principal also has `iam:CreatePolicyVersion` on that policy ARN.

### 1.2 SetDefaultPolicyVersion (rollback)
- **Required actions:** `iam:SetDefaultPolicyVersion`
- **Mechanism:** Switch the default version of a managed policy to an older version that has wider permissions. This is the basis of CloudGoat's `iam_privesc_by_rollback` scenario.
- **Source:** Rhino #2; [CloudGoat iam_privesc_by_rollback](https://github.com/RhinoSecurityLabs/cloudgoat)
- **Detection notes:** any principal with `iam:SetDefaultPolicyVersion` on a policy with >1 version.

### 1.3 PassRole + ec2:RunInstances
- **Required actions:** `iam:PassRole`, `ec2:RunInstances`
- **Mechanism:** Launch an EC2 instance with an existing privileged instance profile and read role credentials from IMDS, or smuggle commands via user-data.
- **Source:** Rhino #3; [PMapper ec2_edges.py](https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/ec2_edges.py)
- **Detection notes:** `iam:PassRole` without `iam:PassedToService` condition + any `ec2:Run*`.

### 1.4 PassRole + ec2:RunInstances + iam:CreateInstanceProfile + iam:AddRoleToInstanceProfile
- **Required actions:** `iam:PassRole`, `iam:CreateInstanceProfile`, `iam:AddRoleToInstanceProfile`, `ec2:RunInstances`
- **Mechanism:** Same as 1.3 but for roles that don't yet have an instance profile attached. Attacker constructs the profile, attaches the role, launches the instance.
- **Source:** PMapper ec2_edges
- **Detection notes:** chain of profile-creation + RunInstances.

### 1.5 ec2:AssociateIamInstanceProfile (post-launch)
- **Required actions:** `iam:PassRole`, `ec2:RunInstances`, `ec2:AssociateIamInstanceProfile`
- **Mechanism:** Launch a plain EC2 first, then associate a privileged instance profile after the fact, sidestepping policies that scope `RunInstances` by instance-profile ARN.
- **Source:** PMapper ec2_edges
- **Detection notes:** policy allowing `AssociateIamInstanceProfile` separate from `RunInstances`.

### 1.6 CreateAccessKey for another user
- **Required actions:** `iam:CreateAccessKey`
- **Mechanism:** Create programmatic credentials for any user with <2 existing keys. Long-lived AKIA credentials become persistence.
- **Source:** Rhino #4; [Pacu iam__backdoor_users_keys](https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details)
- **Detection notes:** `iam:CreateAccessKey` on `Resource:*` or other-user ARNs.

### 1.7 CreateLoginProfile for another user
- **Required actions:** `iam:CreateLoginProfile`
- **Mechanism:** Set a console password for users who don't already have one; log in as them.
- **Source:** Rhino #5; PMapper iam_edges
- **Detection notes:** wildcard or cross-user `iam:CreateLoginProfile`.

### 1.8 UpdateLoginProfile (password reset)
- **Required actions:** `iam:UpdateLoginProfile`
- **Mechanism:** Overwrite an existing console password and authenticate as the target.
- **Source:** Rhino #6; PMapper iam_edges
- **Detection notes:** `iam:UpdateLoginProfile` cross-user.

### 1.9 AttachUserPolicy → AdministratorAccess
- **Required actions:** `iam:AttachUserPolicy`
- **Mechanism:** Attach `arn:aws:iam::aws:policy/AdministratorAccess` (or PowerUserAccess) to attacker's own user.
- **Source:** Rhino #7
- **Detection notes:** any policy granting `iam:AttachUserPolicy` without ARN condition.

### 1.10 AttachGroupPolicy
- **Required actions:** `iam:AttachGroupPolicy` (attacker must already belong to the group)
- **Mechanism:** Attach administrative managed policy to a group the attacker is a member of.
- **Source:** Rhino #8
- **Detection notes:** `iam:AttachGroupPolicy` + attacker's group membership.

### 1.11 AttachRolePolicy
- **Required actions:** `iam:AttachRolePolicy` + `sts:AssumeRole` on target role
- **Mechanism:** Attach an admin policy to a role the attacker can already assume.
- **Source:** Rhino #9
- **Detection notes:** `iam:AttachRolePolicy` paired with any assumable role.

### 1.12 PutUserPolicy / PutGroupPolicy / PutRolePolicy (inline)
- **Required actions:** `iam:PutUserPolicy` / `iam:PutGroupPolicy` / `iam:PutRolePolicy`
- **Mechanism:** Define an arbitrary inline policy (e.g., `Action:*` `Resource:*`) on self, attacker's group, or assumable role. These are the most direct paths.
- **Source:** Rhino #10, #11, #12
- **Detection notes:** any `iam:Put*Policy` without rigid Resource scoping.

### 1.13 AddUserToGroup
- **Required actions:** `iam:AddUserToGroup`
- **Mechanism:** Add self to a privileged existing group.
- **Source:** Rhino #13
- **Detection notes:** `iam:AddUserToGroup` on `Resource:*` or any non-self group ARN.

### 1.14 UpdateAssumeRolePolicy
- **Required actions:** `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole`
- **Mechanism:** Rewrite a role's trust policy so the attacker (or attacker's external account) can assume it. Classic backdoor primitive.
- **Source:** Rhino #14; [Pacu iam__backdoor_assume_role](https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details)
- **Detection notes:** `iam:UpdateAssumeRolePolicy` without `Resource` scoping.

### 1.15 PassRole + lambda:CreateFunction + lambda:InvokeFunction
- **Required actions:** `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction`
- **Mechanism:** Create a Lambda with a privileged execution role; invoke it to run arbitrary code that calls AWS APIs with that role's permissions or exfils its temporary creds.
- **Source:** Rhino #15; [PMapper lambda_edges.py](https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/lambda_edges.py); [HackingTheCloud PassRole abuse](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/)
- **Detection notes:** the canonical PassRole-to-Lambda chain.

### 1.16 PassRole + lambda:CreateFunction + lambda:AddPermission (cross-account)
- **Required actions:** `iam:PassRole`, `lambda:CreateFunction`, `lambda:AddPermission`
- **Mechanism:** Create a Lambda with a privileged role, then grant cross-account invoke via `lambda:AddPermission`. No `lambda:InvokeFunction` on attacker's side needed.
- **Source:** Rhino #16

### 1.17 PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping (DynamoDB trigger)
- **Required actions:** `iam:PassRole`, `lambda:CreateFunction`, `lambda:CreateEventSourceMapping` + a DynamoDB stream
- **Mechanism:** Trigger the malicious Lambda via DynamoDB Streams event-source — no direct InvokeFunction needed.
- **Source:** Rhino #17

### 1.18 lambda:UpdateFunctionCode
- **Required actions:** `lambda:UpdateFunctionCode`
- **Mechanism:** Replace code of an existing Lambda that already has a privileged execution role. No PassRole needed.
- **Source:** Rhino #18; PMapper lambda_edges
- **Detection notes:** `lambda:UpdateFunctionCode` on `Resource:*` is high-impact.

### 1.19 lambda:UpdateFunctionConfiguration (malicious layer)
- **Required actions:** `lambda:UpdateFunctionConfiguration`
- **Mechanism:** Attach a malicious Lambda Layer (or env vars / runtime override) to an existing function with a privileged role. Library shadowing executes attacker code on next invoke.
- **Source:** Rhino "Malicious Layer" extension
- **Detection notes:** UpdateFunctionConfiguration on `Resource:*`.

### 1.20 PassRole + glue:CreateDevEndpoint
- **Required actions:** `iam:PassRole`, `glue:CreateDevEndpoint`
- **Mechanism:** Create a Glue development endpoint with a privileged role; SSH in and read role creds.
- **Source:** Rhino #19

### 1.21 glue:UpdateDevEndpoint (SSH key swap)
- **Required actions:** `glue:UpdateDevEndpoint`
- **Mechanism:** Replace authorized SSH key on an existing Glue dev endpoint; SSH in as the endpoint's role.
- **Source:** Rhino #20

### 1.22 PassRole + glue:CreateJob / glue:UpdateJob
- **Required actions:** `iam:PassRole`, `glue:CreateJob` or `glue:UpdateJob`
- **Mechanism:** Configure a Glue job to use a privileged role; run a job script that exfiltrates the role's STS creds.
- **Source:** HackingTheCloud paths 26-27

### 1.23 PassRole + cloudformation:CreateStack
- **Required actions:** `iam:PassRole`, `cloudformation:CreateStack`
- **Mechanism:** Provide a CFN template that creates a backdoor user / policy and is executed under a privileged role passed via `--role-arn`.
- **Source:** Rhino #21; [PMapper cloudformation_edges.py](https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/cloudformation_edges.py)

### 1.24 cloudformation:UpdateStack (no PassRole)
- **Required actions:** `cloudformation:UpdateStack`
- **Mechanism:** Update an existing stack — the stack already has a privileged service role attached. New template runs with that role.
- **Source:** PMapper cloudformation_edges
- **Detection notes:** `cloudformation:UpdateStack` on stacks with privileged service roles is a hidden privesc primitive.

### 1.25 cloudformation:CreateChangeSet + cloudformation:ExecuteChangeSet
- **Required actions:** `cloudformation:CreateChangeSet`, `cloudformation:ExecuteChangeSet`
- **Mechanism:** Change-set route to alter infrastructure under an existing stack role.
- **Source:** PMapper cloudformation_edges

### 1.26 PassRole + datapipeline:CreatePipeline + datapipeline:PutPipelineDefinition + datapipeline:ActivatePipeline
- **Required actions:** `iam:PassRole`, `datapipeline:CreatePipeline`, `datapipeline:PutPipelineDefinition`, `datapipeline:ActivatePipeline`
- **Mechanism:** Execute arbitrary shell commands as pipeline role.
- **Source:** Rhino #22

### 1.27 codestar:CreateProjectFromTemplate
- **Required actions:** `codestar:CreateProjectFromTemplate` (undocumented API)
- **Mechanism:** Undocumented API spawns CloudFormation under elevated CodeStar service role.
- **Source:** Rhino CodeStar #23

### 1.28 codestar:CreateProject + iam:PassRole
- **Required actions:** `codestar:CreateProject`, `iam:PassRole`
- **Mechanism:** Pass high-privilege role into a new CodeStar project for resource deployment.
- **Source:** Rhino CodeStar #24

### 1.29 codestar:CreateProject + codestar:AssociateTeamMember
- **Required actions:** `codestar:CreateProject`, `codestar:AssociateTeamMember`
- **Mechanism:** Add self as project Owner; CodeStar auto-attaches IAM policies that grant project-wide permissions.
- **Source:** Rhino CodeStar #25

### 1.30 PassRole + sagemaker:CreateNotebookInstance + sagemaker:CreatePresignedNotebookInstanceUrl
- **Required actions:** `iam:PassRole`, `sagemaker:CreateNotebookInstance`, `sagemaker:CreatePresignedNotebookInstanceUrl`
- **Mechanism:** Launch a SageMaker notebook with a privileged role; open a pre-signed URL into the notebook and grab role STS creds from its metadata.
- **Source:** Rhino #27; [PMapper sagemaker_edges.py](https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/sagemaker_edges.py)

### 1.31 sagemaker:CreatePresignedNotebookInstanceUrl (existing notebook)
- **Required actions:** `sagemaker:CreatePresignedNotebookInstanceUrl`
- **Mechanism:** Generate pre-signed URL into an existing privileged notebook; no creation perms needed.
- **Source:** Rhino #28

### 1.32 PassRole + sagemaker:CreateTrainingJob
- **Required actions:** `iam:PassRole`, `sagemaker:CreateTrainingJob`
- **Mechanism:** Submit a training job whose entrypoint runs attacker code under the privileged role.
- **Source:** PMapper sagemaker_edges

### 1.33 PassRole + sagemaker:CreateProcessingJob
- **Required actions:** `iam:PassRole`, `sagemaker:CreateProcessingJob`
- **Mechanism:** Same as 1.32 but with processing jobs.
- **Source:** PMapper sagemaker_edges

### 1.34 PassRole + codebuild:CreateProject + codebuild:StartBuild
- **Required actions:** `iam:PassRole`, `codebuild:CreateProject`, `codebuild:StartBuild` (or `StartBuildBatch`)
- **Mechanism:** Define a CodeBuild project with a privileged service role; the buildspec runs attacker code.
- **Source:** [PMapper codebuild_edges.py](https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/codebuild_edges.py)

### 1.35 codebuild:StartBuild (existing project)
- **Required actions:** `codebuild:StartBuild`
- **Mechanism:** Trigger an existing project that has a privileged role; combine with `codebuild:UpdateProject` if buildspec change is needed.
- **Source:** PMapper codebuild_edges

### 1.36 PassRole + codebuild:UpdateProject + codebuild:StartBuild
- **Required actions:** `iam:PassRole`, `codebuild:UpdateProject`, `codebuild:StartBuild`
- **Mechanism:** Repoint an existing CodeBuild project's role.
- **Source:** PMapper codebuild_edges

### 1.37 ssm:SendCommand against EC2 with privileged role
- **Required actions:** `ssm:SendCommand` (and target must have a privileged instance profile + SSM agent)
- **Mechanism:** Execute commands as root/SYSTEM on any EC2 instance running the SSM agent; steal the instance-profile creds.
- **Source:** [PMapper ssm_edges.py](https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/ssm_edges.py); Pacu `systemsmanager__rce_ec2`
- **Detection notes:** `ssm:SendCommand` on `Resource:*` is fleet-wide RCE.

### 1.38 ssm:StartSession (interactive)
- **Required actions:** `ssm:StartSession`
- **Mechanism:** Open interactive Session Manager session on a privileged EC2 instance.
- **Source:** PMapper ssm_edges

### 1.39 sts:AssumeRole (weak trust policy)
- **Required actions:** `sts:AssumeRole`
- **Mechanism:** Any role whose trust policy lists wildcard or wide principals (entire account `"AWS":"arn:aws:iam::ACCT:root"`) can be assumed laterally.
- **Source:** [PMapper sts_edges.py](https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/sts_edges.py)

### 1.40 sts:AssumeRoleWithSAML / WebIdentity (weak audience/issuer)
- **Required actions:** federated trust policy with permissive `StringEquals` / missing audience condition
- **Mechanism:** Assume role using attacker-controlled identity provider or with mis-scoped GitHub Actions / GitLab OIDC subjects (e.g., `Condition.StringLike: token.actions.githubusercontent.com:sub: "repo:org/*"`).
- **Source:** Multiple advisories; AWS guidance on OIDC for GitHub Actions
- **Detection notes:** OIDC trust policies that use `StringLike` instead of `StringEquals` on `sub`.

### 1.41 sts:GetFederationToken
- **Required actions:** `sts:GetFederationToken`
- **Mechanism:** Generate temporary credentials that survive deletion of the original access key (persistence). Token can also be down-scoped to evade detections that watch the original principal.
- **Source:** [Stratus Red Team](https://stratus-red-team.cloud/attack-techniques/AWS/); HackingTheCloud persistence

### 1.42 PassRole + autoscaling:CreateAutoScalingGroup (+ existing Launch Configuration)
- **Required actions:** `autoscaling:CreateAutoScalingGroup` (+ implicit `iam:CreateServiceLinkedRole`)
- **Mechanism:** Spawn instances using an existing launch configuration that already binds a privileged instance profile.
- **Source:** [PMapper autoscaling_edges.py](https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/autoscaling_edges.py)

### 1.43 PassRole + autoscaling:CreateLaunchConfiguration + autoscaling:CreateAutoScalingGroup
- **Required actions:** `iam:PassRole`, `autoscaling:CreateLaunchConfiguration`, `autoscaling:CreateAutoScalingGroup`
- **Mechanism:** Create a launch config that passes a privileged role, spin up ASG to materialize EC2s with it.
- **Source:** PMapper autoscaling_edges

### 1.44 PassRole + autoscaling:CreateAutoScalingGroup + ec2:CreateLaunchTemplate (template variant)
- **Required actions:** `iam:PassRole`, `ec2:CreateLaunchTemplate`, `autoscaling:CreateAutoScalingGroup`/`UpdateAutoScalingGroup`
- **Mechanism:** Same shape as 1.43 but via launch templates (modern EC2).
- **Source:** [HackingTheCloud path 17](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/)

### 1.45 PassRole + ecs:RunTask
- **Required actions:** `iam:PassRole`, `ecs:RunTask`
- **Mechanism:** Launch a Fargate task with command overrides and a privileged task role.
- **Source:** HackingTheCloud path 23

### 1.46 PassRole + ecs:RegisterContainerInstance + ecs:StartTask + ecs:DeregisterContainerInstance
- **Required actions:** above
- **Mechanism:** Register an attacker-controlled host as an ECS container instance; start a task with the privileged task role.
- **Source:** HackingTheCloud path 24

### 1.47 ecs:RegisterTaskDefinition (backdoor existing task)
- **Required actions:** `ecs:RegisterTaskDefinition`, `ecs:UpdateService`
- **Mechanism:** Replace a task definition with one that exfils the task role's STS creds.
- **Source:** Pacu `ecs__backdoor_task_def`

### 1.48 iam:DeleteRolePolicy / iam:DetachRolePolicy / iam:DeleteUserPolicy / iam:DetachUserPolicy (deny removal)
- **Required actions:** any of above
- **Mechanism:** Remove a policy that contains explicit `Deny` statements. Effective permissions increase.
- **Source:** HackingTheCloud paths 11, 13-15
- **Detection notes:** detach permissions paired with policies that contain Deny.

### 1.49 iam:DeleteRolePermissionsBoundary / iam:DeleteUserPermissionsBoundary
- **Required actions:** above
- **Mechanism:** Delete the permissions boundary, removing the ceiling on effective permissions.
- **Source:** HackingTheCloud paths 10, 12

### 1.50 iam:PutRolePermissionsBoundary / iam:PutUserPermissionsBoundary
- **Required actions:** above
- **Mechanism:** Replace boundary with a less-restrictive policy.
- **Source:** HackingTheCloud paths 32, 34

### 1.51 PassRole + bedrock-agentcore:CreateCodeInterpreter + bedrock-agentcore:InvokeCodeInterpreter
- **Required actions:** above
- **Mechanism:** Pass a privileged role to a Bedrock AgentCore code-interpreter; execute arbitrary Python under that role.
- **Source:** HackingTheCloud path 18; CloudGoat `agentcore_identity_confusion`

### 1.52 IAM Identity Center (`sso-admin`) privesc primitives
- **Required actions:** `sso-admin:AttachManagedPolicyToPermissionSet`, `sso-admin:AttachCustomerManagedPolicyReferenceToPermissionSet`, `sso-admin:PutInlinePolicyToPermissionSet`, `sso-admin:CreateAccountAssignment`, `sso-admin:DetachManagedPolicyFromPermissionSet`, `identitystore:CreateGroupMembership`
- **Mechanism:** Modify or assign permission sets across an entire AWS Organization; or add a target user to an admin group. Single-account IAM scopers often miss the org-wide blast radius.
- **Source:** [CloudQuery: AWS Identity Center privesc](https://www.cloudquery.io/blog/aws-priv-esc-identity-center)
- **Detection notes:** the `sso-admin:` prefix and `identitystore:CreateGroupMembership` together are an admin-grade combination.

### 1.53 EKS access entries (`eks:AssociateAccessPolicy`, `eks:CreateAccessEntry`)
- **Required actions:** `eks:CreateAccessEntry`, `eks:AssociateAccessPolicy`, `eks:AccessKubernetesApi`
- **Mechanism:** Map an attacker-controlled IAM principal to the Kubernetes `cluster-admin` access policy on an EKS cluster, bypassing the legacy aws-auth ConfigMap.
- **Source:** [AWS docs: access entries](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html)
- **Detection notes:** `eks:CreateAccessEntry` + `eks:AssociateAccessPolicy` is a single-shot cluster takeover combo.

### 1.54 IAM Roles Anywhere trust-anchor abuse
- **Required actions:** `rolesanywhere:CreateTrustAnchor`, `rolesanywhere:CreateProfile`, plus a role with `rolesanywhere.amazonaws.com` in trust policy
- **Mechanism:** Register an attacker CA as a trust anchor and create a profile that maps the CA to existing privileged roles; mint X.509-derived STS creds indefinitely from outside AWS.
- **Source:** [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/aws-roles-anywhere/); [Stratus Red Team](https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.rolesanywhere-create-trust-anchor/)
- **Detection notes:** any IAM policy granting `rolesanywhere:Create*` should be high-risk.

### 1.55 iam:CreateOpenIDConnectProvider + iam:UpdateAssumeRolePolicy
- **Required actions:** above
- **Mechanism:** Add a rogue OIDC IdP, then update a role's trust policy to trust it; assume the role via JWT minted from attacker IdP.
- **Source:** [HackingTheCloud persistence](https://hackingthe.cloud/aws/post_exploitation/iam_persistence/)

### 1.56 iam:CreateSAMLProvider variant
- **Required actions:** `iam:CreateSAMLProvider`, `iam:UpdateAssumeRolePolicy`
- **Mechanism:** SAML version of 1.55.
- **Source:** HackingTheCloud persistence

### 1.57 Eventual-consistency persistence
- **Required actions:** any privileged role recently created
- **Mechanism:** Use STS sessions issued before role/policy deletion — they remain valid for the session duration (default 1h, can be 12h). Attacker stockpiles long-lived sessions in advance of detection.
- **Source:** [HackingTheCloud: IAM Persistence through Eventual Consistency](https://hackingthe.cloud/aws/post_exploitation/iam_persistence_eventual_consistency/)

### 1.58 ECS undocumented protocol abuse (2024)
- **Required actions:** ECS container with `taskRoleArn` and access to the agent introspection endpoint
- **Mechanism:** Independent research disclosed in 2024 demonstrated that ECS uses an undocumented protocol allowing a co-resident container/task to acquire IAM permissions beyond what was assigned, enabling cross-task privilege escalation on the same instance.
- **Source:** [Aviatrix research on ECS 2024 IAM hijacking](https://aviatrix.ai/threat-research-center/amazon-ecs-2024-privilege-escalation-iam-hijacking/)

### 1.59 App Runner service role abuse
- **Required actions:** `iam:PassRole`, `apprunner:CreateService`/`apprunner:UpdateService`
- **Mechanism:** Pass a privileged role to an App Runner service that runs attacker-supplied container/code.
- **Source:** Pathfinding.cloud (Bollina Bhagavan / Appsecco research)

### 1.60 Bedrock AgentCore identity confusion
- **Required actions:** `bedrock-agentcore:*` on shared code interpreters
- **Mechanism:** Manage Bedrock AgentCore code interpreters in a way that gives access to other agents' sensitive data and knowledge-bases.
- **Source:** CloudGoat `agentcore_identity_confusion`

---

## Section 2: Pacu Framework Modules

Pacu is the canonical AWS post-exploitation framework — each module encodes a concrete IAM-action combination an attacker can use. Source: [Pacu Module Details wiki](https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details).

### 2.1 ESCALATE category
- **iam__privesc_scan** — automates Rhino's privesc paths (above). Actions: `iam:GetUser`, `iam:ListAttachedUserPolicies`, `iam:GetUserPolicy`, plus whichever path it abuses.
- **cfn__resource_injection** — Resource Injection in CloudFormation templates. Actions: `s3:PutBucketNotification`, `lambda:CreateFunction`, `iam:CreateRole`.

### 2.2 PERSIST category
- **iam__backdoor_assume_role** — `iam:UpdateAssumeRolePolicyDocument` to add attacker account to role trust.
- **iam__backdoor_users_keys** — `iam:CreateAccessKey` against other users.
- **iam__backdoor_users_password** — `iam:CreateLoginProfile` for passwordless users.
- **lambda__backdoor_new_users** — Creates a Lambda + EventBridge rule that creates access keys whenever a new IAM user is created. Actions: `lambda:CreateFunction`, `events:PutRule`, `iam:CreateAccessKey`. This is the canonical "trigger on iam:CreateUser" persistence pattern.
- **lambda__backdoor_new_roles** — same shape, but for `iam:CreateRole`. Updates trust policy to include attacker.
- **lambda__backdoor_new_sec_groups** — EventBridge rule + Lambda adds backdoor SG ingress on any new SG.
- **ec2__backdoor_ec2_sec_groups** — direct `ec2:AuthorizeSecurityGroupIngress` for backdoor.

### 2.3 EXPLOIT category
- **systemsmanager__rce_ec2** — `ssm:CreateAssociation`, `ssm:SendCommand`, `iam:PassRole`.
- **ec2__startup_shell_script** — stop/modify-userdata/start cycle for code execution. Actions: `ec2:StopInstances`, `ec2:ModifyInstanceAttribute`, `ec2:StartInstances`.
- **ecs__backdoor_task_def** — `ecs:DescribeTaskDefinition`, `ecs:RegisterTaskDefinition`.
- **cognito__attack** — `cognito-idp:AdminCreateUser`, `cognito-identity:GetCredentialsForIdentity`.
- **api_gateway__create_api_keys** — `apigateway:CreateApiKey`.
- **lightsail__***  — `lightsail:CreateKeyPair`, `lightsail:CreateInstanceAccessDetails`, `lightsail:GetKeyPair`, `lightsail:ImportKeyPair` for Lightsail backdoors (often forgotten service).

### 2.4 EXFIL category
- **ebs__download_snapshots** — `ec2:DescribeSnapshots`, `ebs:GetSnapshotBlock` (EBS direct API).
- **rds__explore_snapshots** — `rds:CreateDBSnapshot`, `rds:RestoreDBInstanceFromDBSnapshot`, `rds:ModifyDBInstance` — clone DB to attacker-controlled instance and read.
- **s3__download_bucket** — `s3:ListBucket`, `s3:GetObject`.

### 2.5 LATERAL_MOVE category
- **organizations__assume_role** — `sts:AssumeRole`, `organizations:ListAccounts`; tries default role names (`OrganizationAccountAccessRole`) in every member account.
- **cloudtrail__csv_injection** — `cloudtrail:CreateTrail`, `ec2:RunInstances`; inject formula payloads into CloudTrail downloads that admins import to Excel.
- **vpc__enum_lateral_movement** — `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeVpnConnections`.
- **sns__subscribe** — `sns:Subscribe` to exfil messages.

### 2.6 EVADE category
- **detection__disruption** — `cloudtrail:StopLogging`, `guardduty:DeleteDetector`, `config:DeleteConfigRule`.
- **guardduty__whitelist_ip** — `guardduty:CreateThreatIntelSet` to mark attacker IPs as trusted.
- **cloudtrail__download_event_history** — read logs to learn what is monitored.

### 2.7 RECON_UNAUTH (cross-account enumeration)
- **iam__enum_roles** / **iam__enum_users** — abuse the trust-policy validation error oracle: AWS returns different errors for valid vs invalid role/user names in another account. Action: `iam:UpdateAssumeRolePolicyDocument`.
- **ebs__enum_snapshots_unauth** — enumerate public/shared EBS snapshots by keyword/account.

---

## Section 3: CloudGoat Scenarios (Vulnerable-by-Design)

Each scenario encodes a real IAM misconfiguration pattern. Source: [Rhino CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat).

### 3.1 iam_privesc_by_attachment
- **Pattern:** principal has `iam:AddRoleToInstanceProfile` + `ec2:AssociateIamInstanceProfile` but not `iam:PassRole` directly — attaches an existing high-privilege instance profile to an existing EC2 instance they control. Tests scorers that only flag `iam:PassRole`.

### 3.2 iam_privesc_by_rollback
- **Pattern:** `iam:SetDefaultPolicyVersion` on a policy with stale, more-permissive prior versions. (Section 1.2)

### 3.3 iam_privesc_by_key_rotation
- **Pattern:** A role intended to rotate other users' credentials. Weak rotation logic lets the rotator extract creds and assume the admin role.

### 3.4 lambda_privesc
- **Pattern:** `lambda:UpdateFunctionCode` or `lambda:CreateFunction` + `iam:PassRole` chain.

### 3.5 vulnerable_lambda
- **Pattern:** A Lambda function that applies policies based on user-controlled input — confused-deputy via business logic.

### 3.6 cloud_breach_s3
- **Pattern:** Reverse-proxy SSRF → EC2 IMDS → role creds → S3 (the Capital One pattern).

### 3.7 ec2_ssrf
- **Pattern:** Lambda env var with hardcoded creds → EC2 SSRF web app → IMDS → privileged S3.

### 3.8 ecs_takeover / ecs_efs_attack / ecs_privesc_evade_protection
- **Pattern:** Web RCE in container → IMDS → task role → tag-based policy manipulation → admin EC2 → EFS mount.

### 3.9 codebuild_secrets
- **Pattern:** CodeBuild env vars containing IAM keys; CodeBuild service role over-privileged.

### 3.10 beanstalk_secrets
- **Pattern:** Beanstalk env vars expose secondary credentials; the EB instance profile has admin-adjacent privileges.

### 3.11 detection_evasion
- **Pattern:** Read secrets from Secrets Manager without triggering GuardDuty or CloudTrail alarms — usually by using assumed-role sessions and avoiding LookupEvents-known IPs.

### 3.12 rce_web_app
- **Pattern:** Web RCE on EC2 → RDS access, OR S3-stored SSH keys → direct shell.

### 3.13 glue_privesc
- **Pattern:** SQL injection in CSV ingestion → credential leak → Glue job reverse shell.

### 3.14 sns_secrets / sqs_flag_shop / static
- **Pattern:** Resource-based policy misuse: SNS topic subscription leaking API keys; S3 supply-chain (overwrite JS) attacks.

### 3.15 bedrock_agent_hijacking / agentcore_identity_confusion
- **Pattern:** `bedrock:InvokeAgent` + `lambda:UpdateFunctionCode` chain — agent's Lambda handler is replaced to redirect S3 flag.

### 3.16 vulnerable_cognito
- **Pattern:** Cognito user pool / identity pool misconfigurations that allow signup-without-validation and elevated identity-pool role.

### 3.17 secrets_in_the_cloud
- **Pattern:** Limited IAM user → enumerate to find role → assume → Secrets Manager.

---

## Section 4: Resource-Based Policy Abuse

Source: [HackingTheCloud: Misconfigured Resource-Based Policies](https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/), [Datadog Security Labs: Public S3 bucket policy](https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/s3-bucket-public-policy/).

### 4.1 S3 bucket policy `Principal: "*"` with `s3:PutObject`
- Anyone can overwrite objects — supply-chain attack (Twilio JS-SDK overwrite case is the canonical example).

### 4.2 S3 bucket policy `Principal: "*"` with `s3:GetObject`
- Public read — data exfil. Common via misuse of "all authenticated users" or NotPrincipal-everything-else.

### 4.3 SNS topic policy with wildcard `sns:Subscribe`
- Any AWS principal subscribes to attacker-controlled HTTPS endpoint and exfiltrates messages.

### 4.4 SQS queue policy with wildcard `sqs:ReceiveMessage` or `sqs:SendMessage`
- Read/inject queue contents.

### 4.5 Lambda function policy with wildcard via `lambda:AddPermission` (no `aws:SourceArn`)
- Any AWS account that creates an event-source mapping (e.g., S3 event, SNS) can invoke the function. The AWS docs explicitly call out: "If you add a permission without providing the source ARN, any AWS account that creates a mapping to your function ARN can send events to invoke your Lambda function." Source: [AWS Lambda permission docs](https://docs.aws.amazon.com/lambda/latest/dg/permissions-function-cross-account.html).

### 4.6 KMS key policy `Principal: "*"` (or wide AWS account principal)
- `kms:Decrypt` + `kms:GenerateDataKey` exposes all data encrypted under that key. AWS recommends *never* using `Resource: "*"` for `kms:Decrypt` in identity policies because of cross-account ciphertext exposure. Source: [AWS KMS best practices](https://docs.aws.amazon.com/kms/latest/developerguide/iam-policies-best-practices.html).

### 4.7 ECR repository policy with wildcard `ecr:GetAuthorizationToken` / `ecr:BatchGetImage`
- Image pull / poisoning from any principal.

### 4.8 Secrets Manager resource policy `Principal: "*"` with `secretsmanager:GetSecretValue`
- Secret exfil.

### 4.9 EFS file-system policy with wide `elasticfilesystem:ClientMount`
- Cross-VPC mount.

### 4.10 API Gateway resource policy allows when `AWS_IAM` authorizer is OFF
- If `authorizationType` is not `AWS_IAM`, IAM policy on the principal doesn't apply — the API is effectively public. Source: [API Gateway IAM docs](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html).

### 4.11 IAM role trust policy with `"Principal":{"AWS":"*"}`
- Anyone in any AWS account can `sts:AssumeRole`. Mitigated only by an external ID condition.

### 4.12 IAM role trust with `"Principal":{"AWS":"arn:aws:iam::ACCOUNT:root"}` and no MFA / no external ID
- Any principal in the named account, including freshly created ones, can assume.

### 4.13 RAM share / shared snapshot / shared AMI
- Resources made public via `ec2:ModifyImageAttribute` (AMI), `ec2:ModifySnapshotAttribute` (EBS), `rds:ModifyDBSnapshotAttribute` (RDS). Stratus Red Team `aws.exfiltration.*-share` techniques.

### 4.14 Lambda function URL with `AuthType: NONE`
- Public HTTP endpoint backed by Lambda execution role.

### 4.15 Cross-account `iam:PassRole` via service-resource policy
- Some services accept a role ARN via resource configuration without the *invoker* needing `iam:PassRole` (e.g., older Step Functions, Glue triggers) — a common scoper miss.

---

## Section 5: Real-World Incidents

### 5.1 Capital One (2019)
- **Root cause chain:** open-source WAF on EC2 instance → SSRF in customer-facing request handling → request to `169.254.169.254` IMDSv1 → `WAF-Role` STS creds → `s3:ListAllMyBuckets` + `s3:GetObject` on 700+ buckets.
- **IAM patterns:** (a) IMDSv1 unauthenticated; (b) WAF instance role had `s3:List*` `Resource:*` and `s3:GetObject` `Resource:*` — far beyond what a WAF needs; (c) no S3 bucket policy `Deny` for unexpected principals.
- **Source:** [Krebs](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/), [Appsecco analysis](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af).

### 5.2 Code Spaces (2014)
- **Root cause:** root account / EC2 console without MFA; attacker DDoS extortion led admin to attempt password reset, attacker noticed and deleted EC2 instances, EBS volumes, AMIs, and offsite S3 backups. Business closed in ~12h.
- **IAM patterns:** (a) root used as operational identity; (b) no MFA on console; (c) no `Deny` SCPs / no cross-account backup isolation; (d) S3 backup buckets accessible from the same identity as primary.
- **Source:** [ManageEngine post-mortem](https://blogs.manageengine.com/it-security/passwordmanagerpro/2014/08/20/code-spaces-aws-security-breach-a-sad-reminder-of-the-importance-of-cloud-environment-password-management.html).

### 5.3 Imperva (2019)
- **Root cause:** internet-exposed internal compute instance leaked an AWS API key → attacker used that key to read an RDS snapshot from the migration project.
- **IAM patterns:** (a) long-lived AKIA on internal instance with `rds:DescribeDB*` and `s3:GetObject` on snapshot bucket; (b) snapshot not encrypted with a customer-restricted KMS key; (c) shared snapshot ACLs not constrained.
- **Source:** [Help Net Security](https://www.helpnetsecurity.com/2019/10/11/imperva-security-incident-details/).

### 5.4 Uber (2022)
- **Root cause:** contractor MFA fatigue → corporate VPN → PowerShell script with admin creds for Thycotic-style secret manager → AWS root, GSuite, OneLogin.
- **IAM patterns:** (a) no throttle on MFA push; (b) hardcoded admin credentials in script on share; (c) excessive blast radius from a single privileged identity (AWS, GSuite, IdP all under one secret manager).
- **Source:** [InfoQ](https://www.infoq.com/news/2022/09/Uber-breach-mfa-fatigue/).

### 5.5 SCARLETEEL (2023-2024, Sysdig)
- **Root cause:** vulnerable JupyterLab container in EKS → IMDS (v1+v2) → node IAM role → S3 + Lambda enum → cross-account role assumption to attacker accounts.
- **IAM patterns:** (a) wide `s3:GetObject` / `lambda:GetFunction` on node role; (b) cross-account trust policies the attacker repurposed; (c) S3-compatible 3rd-party endpoints used for exfil to evade CloudTrail.
- **Source:** [Sysdig SCARLETEEL 2.0](https://www.sysdig.com/blog/scarleteel-2-0).

### 5.6 JINX-2401 LLM hijacking (Wiz, 2024-2025)
- **Root cause:** compromised AKIA → `bedrock:InvokeModel` / `bedrock:InvokeModelWithResponseStream` against victim account → resold model access.
- **IAM patterns:** persistence via `iam:CreateUser` + `iam:CreatePolicy` + `iam:CreateAccessKey` + `iam:CreateLoginProfile` to set up `PutUseCaseForModelAccess` and `CreateFoundationModelAgreement` workflows; missing SCPs on `bedrock:*`; user-creation naming pattern `^[A-Z][a-z]{5}[0-9]{3}$`, custom policy "New_Policy". 
- **Source:** [Wiz blog](https://www.wiz.io/blog/jinx-2401-llm-hijacking-aws).

### 5.7 LLMjacking (general, 2024-2026)
- Wider campaign — attackers enable Bedrock model access programmatically: `bedrock:PutUseCaseForModelAccess`, `bedrock:PutFoundationModelEntitlement`, `bedrock:CreateFoundationModelAgreement`, `bedrock:ListFoundationModelAgreementOffers`, then `InvokeModel*`.
- **Source:** [CSO Online](https://www.csoonline.com/article/3535433/llmjacking-how-attackers-use-stolen-aws-credentials-to-enable-llms-and-rack-up-costs-for-victims.html); [AWS TTC](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1496.A007.html).

### 5.8 ECS undocumented protocol (2024 disclosure)
- ECS task isolation gap allowed cross-task IAM token theft via undocumented agent protocol.
- **Source:** [Aviatrix research](https://aviatrix.ai/threat-research-center/amazon-ecs-2024-privilege-escalation-iam-hijacking/).

---

## Section 6: CloudSplaining High-Risk Action Categories

Source: [Salesforce CloudSplaining docs](https://github.com/salesforce/cloudsplaining/blob/master/docs/index.md).

### 6.1 Data Exfiltration
- `s3:GetObject`, `ssm:GetParameter`, `ssm:GetParameters`, `ssm:GetParametersByPath`, `secretsmanager:GetSecretValue`, `dynamodb:Scan`, `dynamodb:Query`, `dynamodb:GetItem`, `rds:DownloadDBLogFilePortion`, `redshift:GetClusterCredentials`.

### 6.2 Resource Exposure (modifying resource-based policies)
- `ecr:DeleteRepositoryPolicy`, `ecr:SetRepositoryPolicy`, `s3:DeleteBucketPolicy`, `s3:PutBucketPolicy`, `s3:DeleteAccessPointPolicy`, `s3:PutAccessPointPolicy`, `s3:BypassGovernanceRetention`, `kms:PutKeyPolicy`, `lambda:AddPermission`, `secretsmanager:PutResourcePolicy`, `sns:AddPermission`, `sqs:AddPermission`, `glacier:SetVaultAccessPolicy`, `iam:UpdateAssumeRolePolicy`.

### 6.3 Privilege Escalation
- Sourced from Rhino paths (Section 1). The full set Cloudsplaining ships.

### 6.4 Infrastructure Modification
- Broad `Action:*` / `Service:*` like `ec2:*`, `s3:*`, `rds:*` on `Resource:*` — also `s3:DeleteBucket`, `ec2:TerminateInstances`, `rds:DeleteDBInstance`, `kms:ScheduleKeyDeletion`.

### 6.5 Credentials Exposure
- `iam:CreateAccessKey`, `iam:UpdateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:CreateServiceSpecificCredential`, `iam:ResetServiceSpecificCredential`, `iam:UploadSSHPublicKey`, `redshift:GetClusterCredentials`, `sts:GetFederationToken`, `sts:GetSessionToken`, `chime:CreateApiKey`.

### 6.6 Compute Service Assumption
- Roles assumable by `ec2.amazonaws.com`, `ecs-tasks.amazonaws.com`, `eks.amazonaws.com`, `lambda.amazonaws.com` are extra-risky when those compute fronts the internet.

---

## Section 7: AWS IAM Access Analyzer Finding Taxonomy

Source: [AWS IAM Access Analyzer findings docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html).

### 7.1 External Access Findings
- Resource-based policy grants access to a principal *outside the zone of trust* (organization or account). Resources analyzed include: S3 buckets/access points, IAM roles (trust policy), KMS keys, Lambda functions/layers, SQS queues, Secrets Manager secrets, ECR repositories, EFS file systems, SNS topics, RDS DB snapshots/cluster snapshots, EBS snapshots, EventBridge buses, DynamoDB streams/tables, OpenSearch domains, etc.

### 7.2 Internal Access Findings
- Access paths *within* the org/account between IAM principals and resources. Useful for blast-radius enumeration.

### 7.3 Unused Access Findings
- Sub-types: **Unused role**, **Unused IAM user access key**, **Unused password**, **Unused permission** (action-level / service-level).

### 7.4 Custom Policy Check findings
- `ValidatePolicy` (syntactic), `CheckAccessNotGranted`, `CheckNoNewAccess`, `CheckNoPublicAccess`. Programmatic gates for CI/CD.

### 7.5 Validation Check IDs (subset relevant to risk)
Reference: [policy validation check reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html).
- `PASS_ROLE_WITH_STAR_IN_RESOURCE` — `iam:PassRole` with `Resource:*`.
- `MISSING_PRINCIPAL` / `INVALID_PRINCIPAL_FORMAT`.
- `DEPRECATED_GLOBAL_CONDITION_KEY`.
- `MISSING_VERSION` — policy without explicit `Version: "2012-10-17"` defaults to legacy semantics.
- `STAR_IN_ACTION` — wildcard action.
- `INVALID_ARN_PREFIX_REGION` — typo'd ARNs that evaluate-true.

---

## Section 8: MITRE ATT&CK Cloud (IaaS) — IAM-Relevant Techniques

Source: [MITRE ATT&CK enterprise/cloud matrix](https://attack.mitre.org/matrices/enterprise/cloud/).

### 8.1 TA0001 Initial Access
- **T1078.004 Valid Accounts: Cloud Accounts** — stolen AKIA / SSO tokens.

### 8.2 TA0003 Persistence
- **T1098.001 Account Manipulation: Additional Cloud Credentials** — `iam:CreateAccessKey`, `iam:CreateLoginProfile` on another user.
- **T1098.003 Additional Cloud Roles** — `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, `sso-admin:Attach*ToPermissionSet`.
- **T1098.004 SSH Authorized Keys** — for EC2 access via user-data.
- **T1136.003 Create Account: Cloud Account** — `iam:CreateUser`, `iam:CreateRole`.

### 8.3 TA0004 Privilege Escalation
- **T1548.005 Temporary Elevated Cloud Access** — `sts:AssumeRole` JIT abuse.
- All paths in Section 1 map here.

### 8.4 TA0005 Defense Evasion
- **T1562.008 Disable or Modify Cloud Logs** — `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:PutEventSelectors` (event-selector blinding), `s3:PutLifecycleConfiguration` to expire trail bucket, `wafv2:DisassociateWebACL`, `guardduty:DeleteDetector`, `guardduty:UpdateDetector` (disable), `config:DeleteConfigRule`, `config:DeleteDeliveryChannel`, `ec2:DeleteFlowLogs`, `route53:DeleteQueryLoggingConfig`.
- **T1535 Unused/Unsupported Cloud Regions** — operate in a region that doesn't have CloudTrail/GuardDuty enabled.
- **T1078.004** also under defense evasion when leveraging valid creds to look benign.

### 8.5 TA0006 Credential Access
- **T1552.005 Cloud Instance Metadata API** — IMDS theft. The Capital One pattern.
- **T1552.007 Container API** — ECS task metadata endpoint (169.254.170.2).
- **T1552.001 Credentials In Files** — env vars, user-data, S3-stored configs.
- **T1555 Credentials from Password Stores** — `secretsmanager:GetSecretValue`, `ssm:GetParameter` (SecureString).
- **T1212 Exploitation for Credential Access** — IMDSv1 against SSRF; ECS undocumented protocol (2024).

### 8.6 TA0007 Discovery
- **T1580 Cloud Infrastructure Discovery** — `ec2:Describe*`, `iam:List*`, `iam:Get*`, `s3:ListAllMyBuckets`.
- **T1087.004 Account Discovery: Cloud Account** — `iam:ListUsers`, `iam:ListRoles`, `organizations:ListAccounts`.
- **T1526 Cloud Service Discovery** — `aws ec2 describe-regions`, service spend enumeration.

### 8.7 TA0008 Lateral Movement
- **T1021.007 Cloud Services** — `ssm:StartSession`, `eks:AccessKubernetesApi`, EC2 Instance Connect, EC2 Serial Console.

### 8.8 TA0010 Exfiltration
- **T1537 Transfer Data to Cloud Account** — share AMI / EBS snapshot / RDS snapshot to attacker account.
- **T1567 Exfiltration Over Web Service** — S3 to attacker-controlled S3-compatible endpoint (SCARLETEEL pattern).

### 8.9 TA0040 Impact
- **T1485 Data Destruction** — S3 batch delete / `kms:ScheduleKeyDeletion` (ransomware-by-key-deletion).
- **T1486 Data Encrypted for Impact** — S3 ransomware via client-side encryption or via `s3:PutObject` with `SSE-C` attacker-held key.
- **T1496 Resource Hijacking** — cryptominers, **T1496.A007 Bedrock LLM abuse**.

---

## Section 9: Newer-Service Attack Surface (2023-2026)

### 9.1 IAM Identity Center / SSO Admin
Actions to scrutinize: `sso-admin:AttachManagedPolicyToPermissionSet`, `sso-admin:AttachCustomerManagedPolicyReferenceToPermissionSet`, `sso-admin:PutInlinePolicyToPermissionSet`, `sso-admin:DetachManagedPolicyFromPermissionSet`, `sso-admin:DetachCustomerManagedPolicyReferenceFromPermissionSet`, `sso-admin:CreateAccountAssignment`, `sso-admin:DeleteAccountAssignment`, `sso-admin:UpdatePermissionSet`, `identitystore:CreateGroupMembership`, `identitystore:CreateUser`. CLI prefix is `sso-admin` but the policy prefix is `sso:`. Action-name aliasing is a common scoper miss. Source: [CloudQuery](https://www.cloudquery.io/blog/aws-priv-esc-identity-center).

### 9.2 EKS
- `eks:AccessKubernetesApi` — required to use the EKS console proxy; combined with cluster-admin RBAC = cluster admin.
- `eks:CreateAccessEntry` + `eks:AssociateAccessPolicy` — modern path to grant Kubernetes admin without ConfigMap edit.
- `eks:UpdateClusterConfig` — disable public-endpoint restrictions.
- Source: [AWS EKS access entries docs](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html).

### 9.3 Bedrock
- `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, `bedrock:CreateFoundationModelAgreement`, `bedrock:PutUseCaseForModelAccess`, `bedrock:PutFoundationModelEntitlement` — LLMjacking primitives.
- Cross-account InvokeModel — model owner pays. Source: [AWS cross-account Bedrock](https://repost.aws/knowledge-center/bedrock-invoke-with-cross-account).
- `bedrock-agentcore:CreateCodeInterpreter`, `bedrock-agentcore:InvokeCodeInterpreter` — generic Python RCE under passed role.

### 9.4 SSM (fleet-wide RCE)
- `ssm:SendCommand` — RCE on every managed instance; combine with `ec2:DescribeInstances` for fan-out.
- `ssm:StartSession` — interactive shell.
- `ssm:GetParameter` / `ssm:GetParameters` / `ssm:GetParametersByPath` — read SecureString.
- `ssm:CreateAssociation` — persistent recurring command execution.
- `ssm:UpdateDocument` + `ssm:PutDefaultDocumentVersion` — backdoor an SSM document the org uses.
- `ssm-incidents:*` — newer surface.

### 9.5 Lambda + EventBridge persistence
- Pacu's `lambda__backdoor_new_*` modules: `events:PutRule` + `events:PutTargets` + `lambda:CreateFunction` + `lambda:AddPermission`. Trigger pattern: `source: aws.iam` + `detail-type: AWS API Call via CloudTrail` + `eventName: CreateUser/CreateRole`. Persistent automatic backdooring of every new principal.

### 9.6 VPC Endpoint Policy bypass
- Default VPC endpoint policy is `Action:* Resource:* Principal:*` — every IAM-restricted call going through the endpoint is unrestricted *by the endpoint*. Tightening the endpoint policy is often the only practical way to scope `s3:*` in a VPC.

### 9.7 IAM Roles Anywhere
- `rolesanywhere:CreateTrustAnchor`, `rolesanywhere:CreateProfile`, `rolesanywhere:UpdateTrustAnchor`, `rolesanywhere:UpdateProfile` — section 1.54 above.

### 9.8 AWS Verified Access
- `verifiedaccess:CreateVerifiedAccessGroup`, `verifiedaccess:CreateVerifiedAccessEndpoint`, `verifiedaccess:ModifyVerifiedAccessTrustProvider` — modify trust providers / endpoints to expose internal services.

### 9.9 AWS Organizations / SCP
- `organizations:LeaveOrganization` — member account "escapes" the SCP guardrail.
- `organizations:DetachPolicy` / `organizations:UpdatePolicy` — modify SCPs at the management account.

### 9.10 EventBridge Pipes
- `pipes:CreatePipe` + `iam:PassRole` — modern, less-watched alternative to Lambda + Step Functions for chaining privileged role to event source.

### 9.11 App Runner / AppConfig / Apprunner-VPC
- `apprunner:CreateService` + `iam:PassRole` — section 1.59.

### 9.12 CodeCatalyst / CodeDeploy
- `codedeploy:CreateDeployment` with attacker-controlled `appspec` and a deployment that runs lifecycle hooks under the deployment role.

### 9.13 AWS Config / CloudFormation StackSets
- `cloudformation:CreateStackInstances` with org-wide deployment role can fan-out backdoors across the entire org.

### 9.14 AWSServiceRoleForSupport
- AWS managed service-linked role that can `s3:GetObject` on **any unencrypted** S3 object in the account if AWS Support requests it; customers cannot delete it. Watch CloudTrail for unusual access by this principal. Source: [JupiterOne](https://www.jupiterone.com/blog/understanding-suspicious-updates-to-aws-managed-policies).

---

## Section 10: JSON-Grammar / Parser Bypass Techniques

Source: [AWS IAM policy grammar](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html), [Steampipe normalization article](https://steampipe.io/blog/normalizing-aws-iam-policies-for-automated-analysis).

### 10.1 `Statement` may be `{}` or `[{}]`
Both forms are valid. Scorers that assume `policy["Statement"]` is always a list miss single-object policies (and vice-versa).

### 10.2 `Action` / `NotAction` may be `string` or `[string]`
Same shape ambiguity. `"Action":"s3:GetObject"` is valid alongside `"Action":["s3:GetObject"]`.

### 10.3 `Resource` may be `string` or `[string]`
Same ambiguity.

### 10.4 `Principal` may be `string` (only when value is `"*"`), `{"AWS":"*"}`, `{"AWS":"arn"}`, `{"AWS":["arn1","arn2"]}`, `{"Service":"x.amazonaws.com"}`, `{"Service":["a","b"]}`, `{"Federated":"..."}`, or `{"CanonicalUser":"..."}`.
Mixed types in a single policy are common.

### 10.5 `Condition` is `{operator: {key: value-or-list}}`
Two layers of nesting. Values may be string or list. Operators are case-insensitive in evaluation but case-preserving in storage — scorers comparing operators with `==` against `"StringEquals"` may miss `"stringequals"` if a re-emitted policy normalized case.

### 10.6 Case sensitivity quirks
- Action names: **case-insensitive** at evaluation (`s3:getobject` == `s3:GetObject`).
- ARN service prefixes: **case-sensitive**.
- Condition operators: case-insensitive at evaluation but tooling may not normalize.

### 10.7 Trailing `*` vs `?` glob
- `?` matches any single character; `*` matches zero-or-more. Scorers that only treat `*` as wildcard miss `?`-based patterns.

### 10.8 Unicode / homoglyph in resource ARNs
- Some characters render identical to ASCII but bypass exact-match checks; AWS lower-cases certain ARN components but not paths.

### 10.9 Duplicate keys
- JSON spec doesn't define duplicate-key behavior. AWS keeps the *last* value; some tools take the first. A policy with two `Resource` keys can be parsed differently by scorer vs AWS.

### 10.10 Missing `Version` field
- Defaults to "2008-10-17" — which **does not support policy variables** like `${aws:username}`. A policy that scorers parse assuming `2012-10-17` may have inert variables in production.

### 10.11 Effect default
- `Effect` is required, but a missing `Effect` in some import paths gets treated as `Deny` (AWS errors); some custom scorers may treat empty as `Allow`.

### 10.12 `Sid` collisions
- `Sid` values must be unique within a policy. Some tools rely on `Sid` as a primary key for deduplication — collisions can hide policy statements during analysis.

### 10.13 Whitespace in action names
- AWS strips whitespace from actions; tools comparing strings may not, missing `"s3:GetObject "` (trailing space).

### 10.14 Mixed-array `Principal` with both AWS and Service entries
- `{"Principal":{"AWS":"arn:...","Service":"lambda.amazonaws.com"}}` — both lines apply. Tools sometimes parse only one.

### 10.15 `NotPrincipal` ordering
- `NotPrincipal` is rarely valid (only with Deny). Allow + NotPrincipal is silently accepted but the documentation warns it grants "all entities including those outside the account" — many tools don't flag this.

---

## Section 11: Condition-Key Bypass Techniques

Sources: [Condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html), [Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html), [Sysdig: Exploiting IAM misconfigurations](https://www.sysdig.com/blog/iam-security-misconfiguration).

### 11.1 `aws:SourceIp: "0.0.0.0/0"` defeats the condition
- Acts as no restriction. Common typo / default.

### 11.2 `aws:SourceIp` with private CIDR
- AWS rejects requests evaluated via SDK from inside VPC private IPs against `aws:SourceIp` — the *public* IP is what AWS sees. Tools that flag `10.0.0.0/8` in `aws:SourceIp` as "internal-only" miss that **the condition never matches**, effectively granting `*`.

### 11.3 `StringEquals` vs `StringLike` on `sub`
- OIDC trust policies (GitHub Actions, GitLab) often use `StringLike "repo:org/*"` instead of `StringEquals "repo:org/repo:ref:refs/heads/main"` — anyone with a fork or branch can claim the JWT.

### 11.4 Missing condition key (default behavior)
- If a condition key is absent from the request context, standard operators evaluate the condition as not met → for `Allow`, the allow does not apply; for `Deny`, the deny does not apply. A `Deny` statement gated on a key that the request doesn't carry **does not block**.

### 11.5 `IfExists` chaining
- `StringEqualsIfExists`, `BoolIfExists`, etc. evaluate true if the key is missing → can flip a Deny into a permit for unauthenticated/cross-service requests.

### 11.6 `Null` operator inversion
- `"Null":{"aws:MultiFactorAuthAge":"true"}` = "require absence of MFA" — exact opposite of likely intent. Often written by hand and inverted.

### 11.7 `Bool: "true"` vs `Bool: true` (string vs bool)
- AWS evaluates both, but tooling that does strict type comparison may misparse.

### 11.8 `StringLike` with `*`
- `"StringLike":{"s3:prefix":"*"}` — degenerate wildcard, no scoping.

### 11.9 `ForAnyValue` vs `ForAllValues`
- Multi-value semantics: `ForAnyValue:StringLike` succeeds if **any** request key matches. `ForAllValues:StringLike` succeeds if **all** values match (vacuously true if list is empty).
- `ForAllValues` with no values in request context = condition passes → effectively unrestricted.

### 11.10 Policy variable injection (`${aws:username}`)
- `"Resource":"arn:aws:s3:::company-${aws:username}/*"` — if an attacker creates a user named `*` or `..` or with path traversal characters (AWS allows many), they can shape the resource ARN. Username rules permit `=,.@_-+` — and `*` is **not** allowed in usernames, but `+` IS, allowing crafted matches.
- `${aws:userid}` is a more stable variable but rarely used in scoping policies.
- Source: [AWS variables blog](https://aws.amazon.com/blogs/aws/variables-in-aws-access-control-policies/).

### 11.11 Tag-based conditions (`aws:ResourceTag`, `aws:RequestTag`, `aws:PrincipalTag`)
- If the principal can `iam:TagUser` / `iam:TagRole` on self (or the resource has `*:TagResource`), the principal can rewrite their own tag to satisfy the condition.
- Stratus / Sysdig: "tag-based access control without locking tag-modify permissions is self-defeating."

### 11.12 `aws:SourceVpce` / `aws:SourceVpc` bypass
- These keys only populate when traffic actually traverses a VPC endpoint. Cross-region or non-endpoint paths return absent → see 11.4.

### 11.13 `aws:SecureTransport` only enforces TLS for the **first hop**
- If the principal is inside AWS, this is usually true regardless. Often misused as if it were a network restriction.

### 11.14 `aws:RequestedRegion` typo / wildcard
- `"aws:RequestedRegion":"us-east-*"` is a `StringLike` match. With `StringEquals`, the wildcard is literal and **never matches**, effectively granting nothing (or, if in a `Deny`, blocking nothing).

### 11.15 Mismatched operator type
- `"IpAddress":{"aws:username":"alice"}` — using `IpAddress` on a string key. AWS may evaluate as never-matched, which inverts intent if used in a Deny.

### 11.16 `aws:PrincipalOrgID` missing on resource policy that uses `Principal:"*"`
- Common pattern: bucket policy with `Principal:"*"` + `Condition.StringEquals.aws:PrincipalOrgID:"o-xxx"`. Without the condition, the bucket is public.

### 11.17 `kms:ViaService` not pinned
- Allows decrypt only when the call is via a specific AWS service. Missing it lets attackers decrypt via any service.

---

## Section 12: NotAction / NotResource / NotPrincipal Anti-Patterns

Source: [AWS NotAction docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html), [Binadox NotAction risk](https://www.binadox.com/blog/binadox-article-policy-with-effect-allow-and-not-action/).

### 12.1 `Allow` + `NotAction:["iam:*"]` + `Resource:"*"`
- Grants every action across every AWS service *except* `iam:*`. Every new service auto-allowed forever.

### 12.2 `Allow` + `NotResource:["arn:aws:s3:::production/*"]`
- Allows the listed action on **every other resource in AWS**. The escape hatch is that the principal can use the policy to grant themselves access to the protected resource by creating a new policy (since the new-policy ARN isn't `production`).

### 12.3 `Allow` + `NotPrincipal`
- Grants the resource to everyone except listed principals — including principals **outside the account**. AWS docs explicitly warn against this. Tools commonly miss because `NotPrincipal` is rare.

### 12.4 `Deny` + `NotAction:["iam:CreateUser"]` (intended as "deny everything except CreateUser")
- This is the correct shape for narrow-Deny. But tools that flag NotAction in *any* Effect produce false positives — scoring needs Effect awareness.

### 12.5 NotAction with `iam:Pass*` typed wide
- `"NotAction":["iam:PassRole","iam:GetRole"]` is *not* the same as `"NotAction":"iam:Pass*"` — wildcards in NotAction are literal until evaluated; ensure scorer expansion handles both.

---

## Section 13: Service-Aliasing & Action-Naming Edge Cases

### 13.1 SSO `sso-admin` vs `sso` prefixes
- The CLI is `aws sso-admin` but the IAM action prefix is `sso:` (e.g., `sso:AttachManagedPolicyToPermissionSet`). Identity Store uses `identitystore:`. A scorer that filters on action prefix `sso-admin:` will miss everything.

### 13.2 RDS Data API
- `rds-data:ExecuteStatement`, `rds-data:BatchExecuteStatement` — runs SQL against Aurora Serverless without DB credentials, only IAM. Scorers focused on `rds:*` miss it.

### 13.3 Lake Formation
- `lakeformation:GrantPermissions`, `lakeformation:GetDataAccess` — Lake Formation can issue temporary creds for S3 read on registered locations. A principal with **only** `lakeformation:GetDataAccess` and no `s3:*` can still read S3 data via Lake Formation's STS issuance.

### 13.4 KMS aliases vs key IDs
- Policies referencing `alias/foo` may not enforce on `key/uuid` access (KMS resolves alias at evaluation, but Resource-element matching is literal). Source: [KMS alias-authorization](https://docs.aws.amazon.com/kms/latest/developerguide/alias-authorization.html).

### 13.5 EC2 vs autoscaling launch templates
- A launch template lives in `ec2:` (`ec2:CreateLaunchTemplate`), but Auto Scaling consumes them via `autoscaling:*`. PassRole evaluation happens at launch-template creation.

### 13.6 STS service-principal `Service` in trust policy
- `"Service":"ec2.amazonaws.com"` vs `"Service":"ec2.amazon.com.cn"` (China) vs `"Service":"ec2.amazonaws.com.cn"`. Cross-region partition mismatches.

### 13.7 Deprecated service prefixes
- `sdb:` (SimpleDB), `swf:` (Simple Workflow), `mechanicalturk:` — old policies sometimes carry deprecated action names that scorers don't recognize but AWS may still honor.

### 13.8 `s3:PutObject` vs `s3-object-lambda:PutObject`
- Object Lambda has its own action prefix; bypasses scorers that only look at `s3:`.

### 13.9 `cognito-idp` vs `cognito-identity` vs `cognito-sync`
- Three distinct prefixes for the same Cognito family. Privesc via `cognito-idp:AdminCreateUser` + `cognito-identity:GetCredentialsForIdentity`.

### 13.10 `iam:*` does NOT cover `sts:*` or `access-analyzer:*` or `iam-roles-anywhere:*`
- A "lock-down IAM" policy with `Deny iam:*` leaves STS open. Scorers that treat IAM as a single namespace miss this.

### 13.11 `ec2-instance-connect:SendSSHPublicKey` and `ec2-instance-connect:SendSerialConsoleSSHPublicKey`
- Separate prefix from `ec2:`. Stratus Red Team's lateral-movement primitive: push attacker SSH key to any instance.

### 13.12 ARN partition variants
- `arn:aws-cn:*` (China), `arn:aws-us-gov:*` (GovCloud), `arn:aws-iso:*` (C2S). Policies written with only `aws:` partition may not work, or may be bypassed in non-commercial partitions.

### 13.13 `Action:"*"` vs `Action:"*:*"`
- `*` is wildcard for entire action-string. `*:*` is technically invalid but AWS may parse permissively. Scorers should treat any single `*` as full wildcard.

### 13.14 `s3:*` does not include `s3-object-lambda:*`, `s3-outposts:*`, `s3express:*` (S3 Express One Zone)
- A `Deny: s3:*` policy leaves all three alternative S3 surfaces accessible.

---

## Sources & Citations

### Foundational research repositories
- Rhino Security Labs — AWS IAM Privilege Escalation central repo: https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation
- Rhino Security Labs blog part 1: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Rhino Security Labs blog part 2: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/
- Pacu framework: https://github.com/RhinoSecurityLabs/pacu
- Pacu module details wiki: https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details
- CloudGoat: https://github.com/RhinoSecurityLabs/cloudgoat
- CloudGoat 2 intro: https://rhinosecuritylabs.com/aws/introducing-cloudgoat-2/
- NCC Group PMapper: https://github.com/nccgroup/PMapper
- PMapper iam_edges.py: https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/iam_edges.py
- PMapper ec2_edges.py: https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/ec2_edges.py
- PMapper lambda_edges.py: https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/lambda_edges.py
- PMapper ssm_edges.py: https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/ssm_edges.py
- PMapper sts_edges.py: https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/sts_edges.py
- PMapper cloudformation_edges.py: https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/cloudformation_edges.py
- PMapper codebuild_edges.py: https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/codebuild_edges.py
- PMapper sagemaker_edges.py: https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/sagemaker_edges.py
- PMapper autoscaling_edges.py: https://raw.githubusercontent.com/nccgroup/PMapper/master/principalmapper/graphing/autoscaling_edges.py
- Datadog Pathfinding.cloud: https://github.com/DataDog/pathfinding.cloud
- Datadog Stratus Red Team — AWS techniques: https://stratus-red-team.cloud/attack-techniques/AWS/
- HackingTheCloud — IAM privesc: https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
- HackingTheCloud — IAM persistence: https://hackingthe.cloud/aws/post_exploitation/iam_persistence/
- HackingTheCloud — Eventual consistency persistence: https://hackingthe.cloud/aws/post_exploitation/iam_persistence_eventual_consistency/
- HackingTheCloud — Roles Anywhere persistence: https://hackingthe.cloud/aws/post_exploitation/iam_roles_anywhere_persistence/
- HackingTheCloud — Misconfigured resource-based policies: https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/
- Salesforce CloudSplaining: https://github.com/salesforce/cloudsplaining
- CloudSplaining docs: https://github.com/salesforce/cloudsplaining/blob/master/docs/index.md
- Palo Alto Networks IAM-Deescalate: https://github.com/PaloAltoNetworks/IAM-Deescalate
- AWS Threat Technique Catalog: https://aws-samples.github.io/threat-technique-catalog-for-aws/

### AWS official documentation
- IAM Access Analyzer findings: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html
- IAM Access Analyzer policy validation checks: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html
- IAM policy grammar: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
- IAM condition keys: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
- IAM condition operators: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
- IAM NotAction: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html
- IAM NotResource: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html
- IAM NotPrincipal: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html
- IAM policy variables: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
- IAM PassRole: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
- Confused deputy: https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- AdministratorAccess policy: https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html
- KMS best practices: https://docs.aws.amazon.com/kms/latest/developerguide/iam-policies-best-practices.html
- KMS alias authorization: https://docs.aws.amazon.com/kms/latest/developerguide/alias-authorization.html
- Lambda cross-account permissions: https://docs.aws.amazon.com/lambda/latest/dg/permissions-function-cross-account.html
- Lambda resource-based policies: https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html
- API Gateway IAM control: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html
- API Gateway resource-policy examples: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-resource-policies-examples.html
- AWS Bedrock identity-based policies: https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html
- EKS access entries: https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html
- IAM Roles Anywhere trust model: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html
- External ID for cross-account: https://aws.amazon.com/blogs/security/how-to-use-external-id-when-granting-access-to-your-aws-resources/

### MITRE ATT&CK
- Enterprise Cloud matrix: https://attack.mitre.org/matrices/enterprise/cloud/
- Cloud IaaS matrix: https://attack.mitre.org/matrices/enterprise/cloud/iaas/
- TA0004 Privilege Escalation: https://attack.mitre.org/tactics/TA0004/
- T1078.004 Cloud Accounts: https://attack.mitre.org/techniques/T1078/004/
- T1552.005 Cloud Instance Metadata API: https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1552.005.html
- T1496.A007 Bedrock LLM abuse: https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1496.A007.html

### Real-world incidents
- Capital One — Krebs analysis: https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/
- Capital One — Appsecco SSRF analysis: https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af
- Code Spaces 2014: https://blogs.manageengine.com/it-security/passwordmanagerpro/2014/08/20/code-spaces-aws-security-breach-a-sad-reminder-of-the-importance-of-cloud-environment-password-management.html
- Imperva 2019 post-mortem: https://www.helpnetsecurity.com/2019/10/11/imperva-security-incident-details/
- Uber 2022 MFA fatigue: https://www.infoq.com/news/2022/09/Uber-breach-mfa-fatigue/
- Sysdig SCARLETEEL 2.0: https://www.sysdig.com/blog/scarleteel-2-0
- Sysdig SCARLETEEL original: https://sysdig.com/blog/cloud-breach-terraform-data-theft/
- Wiz JINX-2401 LLM hijacking: https://www.wiz.io/blog/jinx-2401-llm-hijacking-aws
- CSO Online LLMjacking: https://www.csoonline.com/article/3535433/llmjacking-how-attackers-use-stolen-aws-credentials-to-enable-llms-and-rack-up-costs-for-victims.html
- Aviatrix — ECS 2024 IAM hijacking: https://aviatrix.ai/threat-research-center/amazon-ecs-2024-privilege-escalation-iam-hijacking/
- Wiz — IMDS abuse hunting: https://www.wiz.io/blog/imds-anomaly-hunting-zero-day

### Vendor research / blogs
- Bishop Fox IAM Vulnerable playground: https://bishopfox.com/blog/aws-iam-privilege-escalation-playground
- Snyk — AWS breaches lessons: https://snyk.io/blog/aws-security-breaches/
- Sysdig — IAM misconfiguration exploitation: https://www.sysdig.com/blog/iam-security-misconfiguration
- Tenable — PassRole risks: https://www.tenable.com/blog/auditing-iampassrole-a-problematic-privilege-escalation-permission
- Apono — 7 PassRole pitfalls: https://www.apono.io/blog/7-pitfalls-to-consider-when-configuring-iampassrole/
- Palo Alto Unit 42 — Roles Anywhere: https://unit42.paloaltonetworks.com/aws-roles-anywhere/
- Palo Alto Unit 42 — Misconfigured IAM compromised workloads: https://unit42.paloaltonetworks.com/iam-roles-compromised-workloads/
- CloudQuery — Identity Center privesc: https://www.cloudquery.io/blog/aws-priv-esc-identity-center
- JupiterOne — Suspicious AWS managed policy updates: https://www.jupiterone.com/blog/understanding-suspicious-updates-to-aws-managed-policies
- Datadog Security Labs — Public S3 bucket policy: https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/s3-bucket-public-policy/
- Datadog Security Labs — Pathfinding.cloud intro: https://securitylabs.datadoghq.com/articles/introducing-pathfinding.cloud/
- Wiz — IAM roles security review: https://www.wiz.io/academy/cloud-security/aws-iam-roles
- Wiz Threat Landscape — IAM privesc: https://threats.wiz.io/all-techniques/iam-privilege-escalation
- Permiso — Hijacking AI infrastructure: https://permiso.io/blog/exploiting-hosted-models
- Steampipe — IAM wildcard guide: https://steampipe.io/blog/aws-iam-policy-wildcards-reference
- Steampipe — IAM policy normalization: https://steampipe.io/blog/normalizing-aws-iam-policies-for-automated-analysis
- Endgame — Lambda cross-account: https://endgame.readthedocs.io/en/latest/risks/lambda-functions/
- Redfox Security — Most dangerous IAM permissions: https://www.redfoxsec.com/blog/most-dangerous-aws-iam-permissions-what-attackers-exploit-and-how-to-defend
- Adan Alvarez — Roles Anywhere persistence (Medium): https://medium.com/@adan.alvarez/how-attackers-can-abuse-iam-roles-anywhere-for-persistent-aws-access-b3ced6935dca
