# Mock credentials

All credentials in this directory follow the `AKIATEST...` pattern so
they are loud-marker-fake.

Stage B agents create the per-scenario cred files; this directory
exists as the staging area + the contract that says NOTHING ELSE
goes here.

## Examples (Stage B will materialize)

`L1-default-test-creds.json`:
```json
{
  "Version": 1,
  "AccessKeyId": "AKIATESTACCESSKEY001",
  "SecretAccessKey": "test/secret/key/do/not/use/in/prod",
  "SessionToken": "test-session-token",
  "Expiration": "2099-12-31T23:59:59Z"
}
```

`L14-rotating-creds-source.py`: a Python script that, when run as
`python L14-rotating-creds-source.py serve --port 17499`, exposes
an HTTP endpoint returning `AKIATEST...` creds with a 5-minute
TTL, refreshing on each request to a NEW `AKIATEST...` value. The
endpoint logs all served keys + the bouncer's last-used key for the
L14 evidence block.
