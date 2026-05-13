import pathlib

from iam_jit.schema import load_request, scaffold_request, validate_request

EXAMPLE = pathlib.Path(__file__).resolve().parents[1] / "examples" / "example-request.yaml"


def test_example_validates() -> None:
    request = load_request(EXAMPLE)
    errors = validate_request(request)
    assert errors == [], errors


def _write_yaml(path: pathlib.Path, body: str) -> pathlib.Path:
    path.write_text(body)
    return path


def test_unknown_apiversion_rejected(tmp_path: pathlib.Path) -> None:
    p = _write_yaml(
        tmp_path / "bad.yaml",
        "apiVersion: not-a-real-version\n"
        "kind: RoleRequest\n"
        "metadata:\n"
        "  requester: {name: x, email: x@example.com}\n"
        "spec:\n"
        "  description: ten-plus-character description\n"
        "  task_intent: {services: [s3], actions: [read]}\n"
        "  accounts: [{account_id: '111111111111'}]\n"
        "  duration: {duration_hours: 1}\n",
    )
    errors = validate_request(load_request(p))
    assert any("apiVersion" in err for err in errors)


def test_invalid_account_id_rejected(tmp_path: pathlib.Path) -> None:
    p = _write_yaml(
        tmp_path / "bad.yaml",
        "apiVersion: iam-jit.dev/v1alpha1\n"
        "kind: RoleRequest\n"
        "metadata:\n"
        "  requester: {name: x, email: x@example.com}\n"
        "spec:\n"
        "  description: ten-plus-character description\n"
        "  task_intent: {services: [s3], actions: [read]}\n"
        "  accounts: [{account_id: 'not-a-number'}]\n"
        "  duration: {duration_hours: 1}\n",
    )
    errors = validate_request(load_request(p))
    assert any("account_id" in err for err in errors)


def test_duration_xor(tmp_path: pathlib.Path) -> None:
    p = _write_yaml(
        tmp_path / "bad.yaml",
        "apiVersion: iam-jit.dev/v1alpha1\n"
        "kind: RoleRequest\n"
        "metadata:\n"
        "  requester: {name: x, email: x@example.com}\n"
        "spec:\n"
        "  description: ten-plus-character description\n"
        "  task_intent: {services: [s3], actions: [read]}\n"
        "  accounts: [{account_id: '111111111111'}]\n"
        "  duration: {duration_hours: 1, not_after: '2026-12-31T00:00:00Z'}\n",
    )
    errors = validate_request(load_request(p))
    assert errors


def test_read_only_request_without_description_is_valid(
    tmp_path: pathlib.Path,
) -> None:
    """Read-only requests don't require a description — the policy and
    explicit access_type are enough self-documentation."""
    p = _write_yaml(
        tmp_path / "ro.yaml",
        "apiVersion: iam-jit.dev/v1alpha1\n"
        "kind: RoleRequest\n"
        "metadata:\n"
        "  requester: {name: x, email: x@example.com}\n"
        "spec:\n"
        "  access_type: read-only\n"
        "  task_intent: {services: [s3], actions: [read]}\n"
        "  accounts: [{account_id: '111111111111'}]\n"
        "  duration: {duration_hours: 1}\n",
    )
    errors = validate_request(load_request(p))
    assert errors == [], errors


def test_read_write_request_requires_description(tmp_path: pathlib.Path) -> None:
    """Read-write requests must explain why — that's the whole point
    of asking for write."""
    p = _write_yaml(
        tmp_path / "rw.yaml",
        "apiVersion: iam-jit.dev/v1alpha1\n"
        "kind: RoleRequest\n"
        "metadata:\n"
        "  requester: {name: x, email: x@example.com}\n"
        "spec:\n"
        "  access_type: read-write\n"
        "  task_intent: {services: [s3], actions: [write]}\n"
        "  accounts: [{account_id: '111111111111'}]\n"
        "  duration: {duration_hours: 1}\n",
    )
    errors = validate_request(load_request(p))
    assert any("description" in err.lower() for err in errors), errors


def test_scaffold_round_trips(tmp_path: pathlib.Path) -> None:
    yaml_text = scaffold_request(
        description="Testing scaffold output passes schema after services are filled",
        accounts=["111111111111"],
        duration_hours=24,
    )
    p = _write_yaml(tmp_path / "scaffold.yaml", yaml_text)
    request = load_request(p)
    request["spec"]["task_intent"]["services"] = ["s3"]
    errors = validate_request(request)
    assert errors == [], errors
