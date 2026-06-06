# ANCHOR Claude Code hooks (placeholder — not active)

This directory is reserved for project-local Claude Code hooks. **Nothing here is wired up yet.** Hooks are configured in `.claude/settings.json` (or `settings.local.json`); placing files here alone does not activate them.

## Why this is a placeholder

Hooks change harness behaviour silently (PreToolUse, PostToolUse, Stop, etc.). On a governance-first codebase that's a doctrine-relevant decision, not a config tweak. They should be added one at a time, each with an explicit founder decision, and each tested locally before being checked in.

## Candidate hooks (do NOT activate without explicit instruction)

1. **PreToolUse / Write+Edit guard** — block writes to `app/`, `tests/`, `migrations/` during review-mode sessions. Useful when running `anchor-security-reviewer` or `anchor-backend-rls-reviewer`. Risk: false positives during legitimate fix sessions.
2. **PreToolUse / Bash guard** — block `git commit`, `git push`, `alembic upgrade`, `alembic downgrade` unless explicitly invoked by the user. Risk: needs a clean "i meant it" override path.
3. **PostToolUse / doctrine sniff** — after any Edit/Write, run `anchor-doctrine-check` on the diff and surface FAILs. Risk: latency; needs to be opt-in per session.
4. **Stop / reporting-block enforcer** — refuse to end a session that touched backend source without the CLAUDE.md reporting block. Risk: annoying during throwaway exploration.

## Activation checklist (when the time comes)

- [ ] Founder decision recorded (which hook, why, scope).
- [ ] Hook script committed here with a clear filename (`block-prod-writes.sh`, etc.).
- [ ] Entry added to `.claude/settings.json` (not `settings.local.json` if it's meant to be shared).
- [ ] Tested locally on a no-op session and a real session.
- [ ] Documented in `REVIEW.md` so reviewers know it's running.

Until then: this README exists so the directory has a reason to be in the tree, and so the next person opening it knows to stop and ask.
