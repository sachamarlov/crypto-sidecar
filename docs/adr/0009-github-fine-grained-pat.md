# 0009 — GitHub fine-grained PAT for the autonomy agent

- Status: accepted
- Date: 2026-04-20
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [security, ci, autonomy]

## Context

Claude Code operates autonomously on this repo (clone, push, PRs, Actions,
secrets). The agent needs Git/GitHub credentials whose blast radius is
strictly limited to this single repository.

## Considered options

- **A. Fine-grained PAT** scoped to `sachamarlov/crypto-sidecar` only,
  90-day expiration, granular permissions.
- **B. Classic PAT** with `repo` + `workflow` scopes — full access to all
  private repos of the account; large blast radius.
- **C. GitHub App** installed on the single repo — best in class but heavy
  for a one-person project.
- **D. SSH deploy key** — no API access (no PR creation, no Actions
  management).

## Decision

Adopt **option A** with these permissions on `sachamarlov/crypto-sidecar`:

- Actions: read/write
- Administration: read/write
- Contents: read/write
- Discussions: read/write
- Issues: read/write
- Metadata: read (mandatory)
- Pull requests: read/write
- Secrets: read/write
- Variables: read/write
- Webhooks: read/write
- Workflows: read/write
- Environments: read/write

Stored locally in the Windows Credential Manager via `gh auth login
--with-token` then forgotten by the agent (not re-cited in any reply, file,
or commit).

## Consequences

**Positive**

- Compromise of the token affects only this single private repo.
- 90-day rotation cap forces hygiene.
- Granted permissions are auditable on the GitHub settings page.

**Negative**

- Fine-grained PATs require manual permission ticking — drift between what
  the agent needs and what the token grants must be tracked here.
- Some bleeding-edge GitHub APIs are not yet covered by fine-grained PATs;
  fall back to a scoped GitHub App if encountered.

## References

- GitHub fine-grained PATs — https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
- `gh auth login --with-token` — https://cli.github.com/manual/gh_auth_login
