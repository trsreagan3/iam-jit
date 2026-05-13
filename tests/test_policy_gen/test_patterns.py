"""Tests for the pattern library's matching semantics."""

from __future__ import annotations

from iam_jit.policy_gen.patterns import ALL_PATTERNS, matched_patterns, _phrase_matches


class TestPhraseMatching:
    def test_substring_match(self):
        assert _phrase_matches("read s3", "read s3 data from prod", ["read", "s3", "data", "from", "prod"])

    def test_token_with_gaps_match(self):
        """`deploy lambda` matches `deploy my lambda` (intervening word)."""
        assert _phrase_matches(
            "deploy lambda",
            "deploy my lambda function for incident response",
            ["deploy", "my", "lambda", "function", "for", "incident", "response"],
        )

    def test_token_order_preserved(self):
        """`deploy lambda` does NOT match `lambda deploy` (wrong order)."""
        assert not _phrase_matches(
            "deploy lambda",
            "first lambda then deploy",
            ["first", "lambda", "then", "deploy"],
        )

    def test_single_token_only_substring(self):
        """Single-token phrases use substring match only (no token-gap)."""
        assert _phrase_matches("decrypt", "decrypt this", ["decrypt", "this"])
        # Doesn't fire on partial-word
        assert _phrase_matches("decrypt", "decryption", ["decryption"])


class TestPatternLibrary:
    def test_all_patterns_have_distinct_names(self):
        names = [p.name for p in ALL_PATTERNS]
        assert len(names) == len(set(names)), "duplicate pattern names"

    def test_deny_actions_subset_of_allow(self):
        """Contract: every pattern's deny_actions ⊆ allow_actions."""
        for p in ALL_PATTERNS:
            assert set(p.deny_actions).issubset(set(p.allow_actions)), (
                f"pattern {p.name!r} has deny_actions not in allow_actions: "
                f"{set(p.deny_actions) - set(p.allow_actions)}"
            )

    def test_all_actions_are_colon_qualified(self):
        """Every action is `service:Action` form."""
        for p in ALL_PATTERNS:
            for a in p.allow_actions:
                assert ":" in a, f"pattern {p.name!r}: action {a!r} missing service prefix"


class TestSpecificPatternMatches:
    def test_s3_read_phrases(self):
        for desc in [
            "read S3 logs",
            "get s3 object",
            "download from s3",
            "list bucket contents",
        ]:
            matched = matched_patterns(desc, ALL_PATTERNS)
            assert any(p.name == "s3-read" for p in matched), f"missed: {desc!r}"

    def test_lambda_deploy_with_intervening_words(self):
        for desc in [
            "deploy lambda",
            "deploy my lambda function",
            "deploy a lambda for prod",
            "update lambda function code",
        ]:
            matched = matched_patterns(desc, ALL_PATTERNS)
            assert any(p.name == "lambda-deploy" for p in matched), f"missed: {desc!r}"

    def test_secrets_read(self):
        matched = matched_patterns("read secret prod-db-password", ALL_PATTERNS)
        assert any(p.name == "secrets-read" for p in matched)

    def test_kms_decrypt_substring(self):
        matched = matched_patterns("I want to decrypt these messages", ALL_PATTERNS)
        assert any(p.name == "kms-decrypt" for p in matched)
