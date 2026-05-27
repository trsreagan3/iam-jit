"""Tests for `iam-jit attach` / `iam-jit detach` (#683 universal setup path).

These cover the FILE-EDITING contract. The full setup->traffic->audit flow
(attach -> real aws call -> ibounce decisions_count ticks -> detach) is
exercised as a live end-to-end UAT against a running ibounce, per the
standing directive that UAT must test the SETUP PROCESS end-to-end, not just
units (see [[uat-tests-setup-end-to-end]]).
"""
from __future__ import annotations

import pathlib

from iam_jit.cli_attach import (
    _SENTINEL,
    attach_aws_config,
    detach_aws_config,
)


def test_attach_writes_endpoint_into_empty_config(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config"
    res = attach_aws_config(
        config_path=cfg, profile="default", endpoint="http://127.0.0.1:8767"
    )
    assert res["status"] == "attached"
    text = cfg.read_text()
    assert "[default]" in text
    assert _SENTINEL in text
    assert "endpoint_url = http://127.0.0.1:8767" in text


def test_attach_is_idempotent(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config"
    attach_aws_config(
        config_path=cfg, profile="default", endpoint="http://127.0.0.1:8767"
    )
    res2 = attach_aws_config(
        config_path=cfg, profile="default", endpoint="http://127.0.0.1:8767"
    )
    assert res2["status"] == "already_attached"
    # endpoint_url appears exactly once (no duplication).
    assert cfg.read_text().count("endpoint_url") == 1


def test_attach_preserves_existing_profiles(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config"
    cfg.write_text(
        "[default]\nregion = us-east-1\n\n[profile prod]\nregion = eu-west-1\n"
    )
    attach_aws_config(
        config_path=cfg, profile="default", endpoint="http://127.0.0.1:8767"
    )
    text = cfg.read_text()
    # operator's existing keys/profiles untouched
    assert "region = us-east-1" in text
    assert "[profile prod]" in text
    assert "region = eu-west-1" in text
    assert "endpoint_url = http://127.0.0.1:8767" in text


def test_attach_refuses_foreign_existing_endpoint(tmp_path: pathlib.Path) -> None:
    # operator already set their own endpoint_url (e.g. localstack) — don't clobber
    cfg = tmp_path / "config"
    cfg.write_text("[default]\nendpoint_url = http://localhost:4566\n")
    res = attach_aws_config(
        config_path=cfg, profile="default", endpoint="http://127.0.0.1:8767"
    )
    assert res["status"] == "refused_existing_endpoint"
    assert res["existing_endpoint"] == "http://localhost:4566"
    # file unchanged
    assert "http://localhost:4566" in cfg.read_text()
    assert "8767" not in cfg.read_text()


def test_attach_named_profile_uses_profile_prefix(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config"
    attach_aws_config(
        config_path=cfg, profile="work", endpoint="http://127.0.0.1:8767"
    )
    assert "[profile work]" in cfg.read_text()


def test_detach_removes_only_iam_jit_lines(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config"
    cfg.write_text("[default]\nregion = us-east-1\n")
    attach_aws_config(
        config_path=cfg, profile="default", endpoint="http://127.0.0.1:8767"
    )
    res = detach_aws_config(config_path=cfg, profile="default")
    assert res["status"] == "detached"
    assert res["removed"] == 2  # sentinel + endpoint_url line
    text = cfg.read_text()
    # operator content preserved; our lines gone
    assert "region = us-east-1" in text
    assert "[default]" in text
    assert "endpoint_url" not in text
    assert _SENTINEL not in text


def test_detach_noop_when_nothing_attached(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config"
    cfg.write_text("[default]\nregion = us-east-1\n")
    res = detach_aws_config(config_path=cfg, profile="default")
    assert res["status"] == "nothing_to_detach"
    assert res["removed"] == 0
    assert cfg.read_text() == "[default]\nregion = us-east-1\n"


def test_attach_writes_backup_before_modifying_existing(
    tmp_path: pathlib.Path,
) -> None:
    cfg = tmp_path / "config"
    cfg.write_text("[default]\nregion = us-east-1\n")
    res = attach_aws_config(
        config_path=cfg, profile="default", endpoint="http://127.0.0.1:8767"
    )
    assert res.get("backup_path")
    assert pathlib.Path(res["backup_path"]).exists()
    # backup holds the pre-attach content
    assert "endpoint_url" not in pathlib.Path(res["backup_path"]).read_text()
