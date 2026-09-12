import json

import pytest

from tools import poh


def registry(*contributors):
    return {"version": 1, "contributors": list(contributors)}


def contributor(github="alice", claims=None):
    if claims is None:
        claims = [
            {"kind": "orcid", "value": "https://orcid.org/0000-0002-1825-0097"},
            {"kind": "gitlab", "value": "https://gitlab.com/alice"},
        ]
    return {"github": github, "claims": claims}


def test_valid_registry_counts_contributors_and_claims():
    assert poh.validate_registry(registry(contributor())) == (1, 2)


@pytest.mark.parametrize(
    "claims,message",
    [
        ([{"kind": "orcid", "value": "https://orcid.org/0000-0002-1825-0097"}], "between 2 and 5"),
        (
            [
                {"kind": "gitlab", "value": "https://gitlab.com/alice"},
                {"kind": "linkedin", "value": "https://linkedin.com/in/alice"},
                {"kind": "matrix", "value": "@alice:example.org"},
                {"kind": "orcid", "value": "https://orcid.org/0000-0002-1825-0097"},
                {"kind": "keyoxide", "value": "https://keyoxide.org/alice"},
                {"kind": "scholar", "value": "https://scholar.google.com/citations?user=alice"},
            ],
            "between 2 and 5",
        ),
    ],
)
def test_registry_rejects_too_few_or_too_many_claims(claims, message):
    with pytest.raises(poh.ValidationError, match=message):
        poh.validate_registry(registry(contributor(claims=claims)))


def test_registry_rejects_duplicate_people_and_claims():
    with pytest.raises(poh.ValidationError, match="duplicate GitHub login"):
        poh.validate_registry(registry(contributor("Alice"), contributor("alice")))

    shared = [
        {"kind": "orcid", "value": "https://orcid.org/0000-0002-1825-0097"},
        {"kind": "gitlab", "value": "https://gitlab.com/shared"},
    ]
    with pytest.raises(poh.ValidationError, match="shared by multiple contributors"):
        poh.validate_registry(registry(contributor("alice", shared), contributor("bob", shared)))


def test_registry_rejects_raw_email_and_tracking_urls():
    raw_email = [
        {"kind": "email", "value": "alice@example.org"},
        {"kind": "gitlab", "value": "https://gitlab.com/alice"},
    ]
    with pytest.raises(poh.ValidationError, match="unsupported claim kind"):
        poh.validate_registry(registry(contributor(claims=raw_email)))

    tracked = [
        {"kind": "linkedin", "value": "https://linkedin.com/in/alice?tracking=1"},
        {"kind": "gitlab", "value": "https://gitlab.com/alice"},
    ]
    with pytest.raises(poh.ValidationError, match="query parameters"):
        poh.validate_registry(registry(contributor(claims=tracked)))


def test_challenge_round_trip_and_subject_binding():
    token, digest, expires = poh.issue_challenge("Alice", ttl=120, now=1000, nonce="A" * 24)
    assert poh.verify_challenge("alice", token, digest, now=1050) == expires
    with pytest.raises(poh.ValidationError, match="not bound"):
        poh.verify_challenge("bob", token, digest, now=1050)


def test_challenge_rejects_tampering_and_expiry():
    token, digest, _ = poh.issue_challenge("alice", ttl=120, now=1000, nonce="A" * 24)
    with pytest.raises(poh.ValidationError, match="does not match"):
        poh.verify_challenge("alice", token[:-1] + "B", digest, now=1050)
    with pytest.raises(poh.ValidationError, match="expired"):
        poh.verify_challenge("alice", token, digest, now=1121)


def test_cli_validates_registry(tmp_path, capsys):
    path = tmp_path / "poh.json"
    path.write_text(json.dumps(registry(contributor())), encoding="utf-8")
    assert poh.main(["registry", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "claims": 2,
        "contributors": 1,
        "valid": True,
    }


def test_verify_commit_never_invokes_a_shell(monkeypatch):
    calls = []

    class Result:
        returncode = 0
        stdout = "good signature"
        stderr = ""

    def fake_run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return Result()

    monkeypatch.setattr(poh.subprocess, "run", fake_run)
    sha = "a" * 40
    assert poh.verify_commit(sha, "/repo") == "good signature"
    assert calls[0][0] == ["git", "-C", "/repo", "verify-commit", sha]
    assert "shell" not in calls[0][1]
