"""Tests for ``iam_jit.bouncer.caveats`` discoverability surfaces.

Per task #304 + ``[[cross-product-agent-parity]]``: the Python module
mirrors the Go ``internal/caveats`` package in gbounce / kbounce /
dbounce. These tests pin the shape so the banner + doctor + MCP +
error-message surfaces stay consistent.
"""

from __future__ import annotations

from iam_jit.bouncer import caveats


def test_all_entries_have_urls() -> None:
    for e in caveats.ENTRIES:
        assert e.id, f"entry without id: {e!r}"
        assert e.anchor, f"entry {e.id} without anchor"
        url = e.url
        assert url.startswith("https://github.com/")
        assert e.anchor in url
        assert e.doctor_blurb, f"entry {e.id} missing doctor_blurb"


def test_by_id_finds_entries() -> None:
    for entry_id in ("B1", "B2", "B3", "B4", "B10", "B11", "B12", "B13", "B14", "B15"):
        assert caveats.by_id(entry_id) is not None, f"{entry_id} not found"
    assert caveats.by_id("BNONE") is None


def test_link_suffix_known() -> None:
    suffix = caveats.link_suffix("B1")
    assert "§B1:" in suffix
    assert "github.com" in suffix
    assert "ibounce-sigv4-only" in suffix


def test_link_suffix_unknown() -> None:
    assert caveats.link_suffix("BNONE") == ""


def test_banner_lines_sigv4_always_on() -> None:
    lines = caveats.banner_lines(caveats.Trigger())
    assert len(lines) == 1, lines
    assert "§B1" in lines[0]


def test_banner_lines_safe_default_adds_b3() -> None:
    lines = caveats.banner_lines(
        caveats.Trigger(safe_default_profile=True),
    )
    assert len(lines) == 2, lines
    joined = "\n".join(lines)
    assert "§B1" in joined
    assert "§B3" in joined


def test_banner_lines_sigv4_off_is_quiet() -> None:
    lines = caveats.banner_lines(
        caveats.Trigger(always_sigv4_only=False),
    )
    assert lines == []


def test_doctor_entries_covers_cross_product() -> None:
    ids = {e.id for e in caveats.doctor_entries()}
    for must in ("B1", "B3", "B4", "B13", "B14", "B15"):
        assert must in ids, f"doctor entries missing {must}"


def test_canonical_doc_url_shape() -> None:
    assert caveats.CANONICAL_DOC_URL.endswith("/KNOWN-CAVEATS.md")
    assert caveats.CANONICAL_DOC_URL.startswith("https://github.com/")
