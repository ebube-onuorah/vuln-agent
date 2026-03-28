"""Unit tests for GitHub PR URL parsing (no network calls)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
from advanced_predictor.github_client import parse_pr_url


class TestParsePrUrl:
    def test_full_https_url(self):
        owner, repo, num = parse_pr_url("https://github.com/anthropics/anthropic-sdk-python/pull/42")
        assert owner == "anthropics"
        assert repo == "anthropic-sdk-python"
        assert num == 42

    def test_url_without_scheme(self):
        owner, repo, num = parse_pr_url("github.com/torvalds/linux/pull/1234")
        assert owner == "torvalds"
        assert repo == "linux"
        assert num == 1234

    def test_shorthand_format(self):
        owner, repo, num = parse_pr_url("owner/repo#99")
        assert owner == "owner"
        assert repo == "repo"
        assert num == 99

    def test_trailing_slash_stripped(self):
        owner, repo, num = parse_pr_url("https://github.com/owner/repo/pull/7/")
        assert owner == "owner"
        assert repo == "repo"
        assert num == 7

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Unrecognized PR format"):
            parse_pr_url("not-a-url")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            parse_pr_url("")

    def test_pr_number_is_int(self):
        _, _, num = parse_pr_url("https://github.com/a/b/pull/123")
        assert isinstance(num, int)

    def test_hyphenated_repo_name(self):
        owner, repo, num = parse_pr_url("https://github.com/vercel/next-js/pull/500")
        assert repo == "next-js"
        assert num == 500
