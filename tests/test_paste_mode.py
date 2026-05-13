import pathlib

from iam_jit.schema import load_request, validate_request


def test_policy_only_validates(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "paste.yaml"
    p.write_text(
        "apiVersion: iam-jit.dev/v1alpha1\n"
        "kind: RoleRequest\n"
        "metadata:\n"
        "  requester: {name: x, email: x@example.com}\n"
        "spec:\n"
        "  description: ten-plus-character description\n"
        "  accounts: [{account_id: '111111111111'}]\n"
        "  duration: {duration_hours: 1}\n"
        "  policy:\n"
        "    Version: '2012-10-17'\n"
        "    Statement:\n"
        "      - Effect: Allow\n"
        "        Action: ['s3:GetObject']\n"
        "        Resource: '*'\n"
    )
    errors = validate_request(load_request(p))
    assert errors == [], errors


def test_neither_task_intent_nor_policy_rejected(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "empty.yaml"
    p.write_text(
        "apiVersion: iam-jit.dev/v1alpha1\n"
        "kind: RoleRequest\n"
        "metadata:\n"
        "  requester: {name: x, email: x@example.com}\n"
        "spec:\n"
        "  description: ten-plus-character description\n"
        "  accounts: [{account_id: '111111111111'}]\n"
        "  duration: {duration_hours: 1}\n"
    )
    errors = validate_request(load_request(p))
    assert errors


def test_malformed_pasted_policy_rejected(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "bad-policy.yaml"
    p.write_text(
        "apiVersion: iam-jit.dev/v1alpha1\n"
        "kind: RoleRequest\n"
        "metadata:\n"
        "  requester: {name: x, email: x@example.com}\n"
        "spec:\n"
        "  description: ten-plus-character description\n"
        "  accounts: [{account_id: '111111111111'}]\n"
        "  duration: {duration_hours: 1}\n"
        "  policy:\n"
        "    Statement:\n"
        "      - Effect: Allow\n"
    )
    errors = validate_request(load_request(p))
    assert any("Version" in err or "policy" in err for err in errors)
