#!/usr/bin/env python3
"""Small, dependency-free helpers for qtop proof-of-humanity reviews."""

from __future__ import print_function

import argparse
import hashlib
import hmac
import json
import re
import secrets
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlparse


CHALLENGE_PREFIX = "qtop-poh-v1"
GITHUB_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
SHA_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
ORCID_RE = re.compile(r"^https://orcid\.org/[0-9]{4}(?:-[0-9]{4}){2}-[0-9]{3}[0-9X]$")
MATRIX_RE = re.compile(r"^@[A-Za-z0-9._=/-]+:[A-Za-z0-9.-]+$")
WEB_CLAIMS = {
    "gitlab": ("gitlab.com", "/"),
    "keyoxide": ("keyoxide.org", "/"),
    "linkedin": ("linkedin.com", "/in/"),
}
ALLOWED_CLAIMS = set(WEB_CLAIMS) | {"matrix", "orcid", "scholar"}


class ValidationError(ValueError):
    """Raised when a PoH artifact is malformed or ambiguous."""


def normalize_github(login):
    if not isinstance(login, str) or not GITHUB_RE.match(login):
        raise ValidationError("invalid GitHub login: {!r}".format(login))
    if "--" in login:
        raise ValidationError("GitHub login cannot contain consecutive hyphens")
    return login.lower()


def normalize_claim(kind, value):
    if kind not in ALLOWED_CLAIMS:
        raise ValidationError("unsupported claim kind: {!r}".format(kind))
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("claim value must be a non-empty string")
    value = value.strip()

    if kind == "matrix":
        if not MATRIX_RE.match(value):
            raise ValidationError("invalid Matrix identifier")
        return kind, value.lower()
    if kind == "orcid":
        if not ORCID_RE.match(value):
            raise ValidationError("invalid ORCID URL")
        return kind, value.lower()

    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port:
        raise ValidationError("claim must be a plain HTTPS profile URL")
    if parsed.fragment:
        raise ValidationError("profile URLs cannot contain fragments")

    if kind == "scholar":
        if host != "scholar.google.com" or parsed.path != "/citations":
            raise ValidationError("invalid Google Scholar profile URL")
        if not parse_qs(parsed.query).get("user"):
            raise ValidationError("Google Scholar URL must contain a user id")
    else:
        expected_host, path_prefix = WEB_CLAIMS[kind]
        if host not in (expected_host, "www." + expected_host):
            raise ValidationError("invalid {} profile host".format(kind))
        if not parsed.path.startswith(path_prefix) or parsed.path == path_prefix:
            raise ValidationError("invalid {} profile path".format(kind))
        if parsed.query:
            raise ValidationError("profile URLs cannot contain query parameters")

    canonical_host = host[4:] if host.startswith("www.") else host
    canonical_path = parsed.path.rstrip("/")
    canonical = "https://{}{}".format(canonical_host, canonical_path)
    if parsed.query:
        canonical += "?" + parsed.query
    return kind, canonical.lower()


def validate_registry(data):
    if not isinstance(data, dict) or set(data) != {"version", "contributors"}:
        raise ValidationError("registry must contain only version and contributors")
    if data["version"] != 1:
        raise ValidationError("unsupported registry version")
    if not isinstance(data["contributors"], list):
        raise ValidationError("contributors must be a list")

    seen_github = set()
    seen_claims = set()
    for index, contributor in enumerate(data["contributors"]):
        label = "contributors[{}]".format(index)
        if not isinstance(contributor, dict) or set(contributor) != {"github", "claims"}:
            raise ValidationError("{} must contain only github and claims".format(label))
        github = normalize_github(contributor["github"])
        if github in seen_github:
            raise ValidationError("duplicate GitHub login: {}".format(github))
        seen_github.add(github)

        claims = contributor["claims"]
        if not isinstance(claims, list) or not 2 <= len(claims) <= 5:
            raise ValidationError("{} must provide between 2 and 5 claims".format(label))
        kinds = set()
        for claim_index, claim in enumerate(claims):
            claim_label = "{}.claims[{}]".format(label, claim_index)
            if not isinstance(claim, dict) or set(claim) != {"kind", "value"}:
                raise ValidationError("{} must contain only kind and value".format(claim_label))
            normalized = normalize_claim(claim["kind"], claim["value"])
            if normalized[0] in kinds:
                raise ValidationError("{} repeats claim kind {}".format(label, normalized[0]))
            if normalized in seen_claims:
                raise ValidationError("claim is shared by multiple contributors: {}".format(normalized[1]))
            kinds.add(normalized[0])
            seen_claims.add(normalized)
    return len(seen_github), len(seen_claims)


def issue_challenge(github, ttl=3600, now=None, nonce=None):
    github = normalize_github(github)
    if not isinstance(ttl, int) or not 60 <= ttl <= 86400:
        raise ValidationError("challenge ttl must be between 60 and 86400 seconds")
    now = int(time.time() if now is None else now)
    nonce = secrets.token_urlsafe(24) if nonce is None else nonce
    if not isinstance(nonce, str) or not re.match(r"^[A-Za-z0-9_-]{20,}$", nonce):
        raise ValidationError("challenge nonce is too short or malformed")
    token = "{}|{}|{}|{}".format(CHALLENGE_PREFIX, github, now + ttl, nonce)
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    return token, digest, now + ttl


def verify_challenge(github, token, expected_digest, now=None):
    github = normalize_github(github)
    try:
        prefix, token_github, expires, nonce = token.split("|", 3)
        expires = int(expires)
    except (AttributeError, TypeError, ValueError):
        raise ValidationError("malformed challenge response")
    if prefix != CHALLENGE_PREFIX or token_github != github:
        raise ValidationError("challenge is not bound to this GitHub login")
    if not re.match(r"^[A-Za-z0-9_-]{20,}$", nonce):
        raise ValidationError("malformed challenge nonce")
    actual_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest.lower()):
        raise ValidationError("challenge digest does not match")
    now = int(time.time() if now is None else now)
    if now > expires:
        raise ValidationError("challenge has expired")
    return expires


def verify_commit(commit, repo="."):
    if not isinstance(commit, str) or not SHA_RE.match(commit):
        raise ValidationError("commit must be a full 40- or 64-character hexadecimal id")
    result = subprocess.run(
        ["git", "-C", repo, "verify-commit", commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip() or "signature verification failed"
        raise ValidationError(detail)
    return (result.stdout or result.stderr).strip()


def _write_json(payload):
    print(json.dumps(payload, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    commands.required = True

    registry = commands.add_parser("registry", help="validate a PoH registry JSON file")
    registry.add_argument("path")

    challenge = commands.add_parser("challenge", help="issue a one-time private challenge")
    challenge.add_argument("github")
    challenge.add_argument("--ttl", type=int, default=3600)

    response = commands.add_parser("response", help="verify a returned challenge")
    response.add_argument("github")
    response.add_argument("token")
    response.add_argument("digest")

    commit = commands.add_parser("commit", help="verify a signed Git commit")
    commit.add_argument("commit")
    commit.add_argument("--repo", default=".")

    args = parser.parse_args(argv)
    try:
        if args.command == "registry":
            with open(args.path, encoding="utf-8") as handle:
                contributors, claims = validate_registry(json.load(handle))
            _write_json({"claims": claims, "contributors": contributors, "valid": True})
        elif args.command == "challenge":
            token, digest, expires = issue_challenge(args.github, args.ttl)
            _write_json({"digest": digest, "expires": expires, "token": token})
        elif args.command == "response":
            expires = verify_challenge(args.github, args.token, args.digest)
            _write_json({"expires": expires, "valid": True})
        else:
            detail = verify_commit(args.commit, args.repo)
            _write_json({"detail": detail, "valid": True})
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("error: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
