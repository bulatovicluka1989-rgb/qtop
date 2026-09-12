# Lightweight proof-of-humanity review

This proof of concept raises the cost of bot and sock-puppet submissions without
collecting identity documents or forcing every contributor through the same
provider. It is a review aid, not proof of a person's legal identity.

## Proposed flow

1. The contributor opens a PR with a signed commit and an AI-assistance
   disclosure when applicable.
2. A small registry entry links the GitHub login to two to five independent,
   public profile claims. Reviewers verify that the linked profiles point back
   to the contributor where the provider supports it.
3. The maintainer runs `tools/poh.py registry poh.json`. The validator rejects
   ambiguous fields, duplicate GitHub logins, duplicate claims, raw email
   addresses, tracking URLs, and unsupported providers.
4. `tools/poh.py commit COMMIT` uses `git verify-commit` to verify the signed
   commit without invoking a shell.
5. When risk justifies another check, a maintainer issues a one-time challenge
   and sends the token through a previously established private channel. Only
   its SHA-256 digest belongs in review notes. The returned token is bound to a
   GitHub login and expiry, so it cannot be reused for another account.
6. A maintainer makes the final decision. Passing these checks never triggers
   an automatic merge.

The registry uses JSON rather than YAML in this prototype. JSON has an
unambiguous standard-library parser, keeps qtop free of a new runtime
dependency, and works on the project's Python 3.6 baseline. If the schema is
accepted, the registry can move to a dedicated `qtop/PoH` repository without
changing the validation rules.

## Registry format

```json
{
  "version": 1,
  "contributors": [
    {
      "github": "alice",
      "claims": [
        {"kind": "orcid", "value": "https://orcid.org/0000-0002-1825-0097"},
        {"kind": "gitlab", "value": "https://gitlab.com/alice"}
      ]
    }
  ]
}
```

Supported claims are ORCID, GitLab, Keyoxide, LinkedIn, Matrix, and Google
Scholar. A claim is a pointer for human review; its format passing validation
does not prove account ownership by itself.

## Commands

```console
python tools/poh.py registry poh.json
python tools/poh.py commit FULL_COMMIT_SHA --repo .
python tools/poh.py challenge alice --ttl 3600
python tools/poh.py response alice PRIVATE_RETURNED_TOKEN STORED_DIGEST
```

The challenge token must not be committed or posted publicly. Email addresses
and other private delivery details are deliberately outside the registry and
the tool.

## Security and usability boundaries

- The checks make bulk impersonation more expensive; they cannot stop a person
  who controls several mature accounts.
- A compromised public profile can still produce a false claim. Maintainers
  should look for reciprocal links, history, and account age.
- A returned challenge proves control of one delivery channel at that moment.
  It does not prove a legal name or continued control.
- Contributors who pass once can reuse their reviewed registry entry on later
  PRs. New challenges should be risk-based instead of mandatory for every PR.
- No identity documents, raw email addresses, or challenge tokens are stored.
- Live demonstrations remain useful for high-risk or hard-to-explain changes.

This keeps the common path short while preserving an explicit escalation path
for suspicious submissions.
