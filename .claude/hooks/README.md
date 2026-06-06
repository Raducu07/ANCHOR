# .claude/hooks — ANCHOR frontend

This directory is a placeholder. **No hooks are configured.**

Hooks for Claude Code run shell commands at lifecycle events (PreToolUse, PostToolUse, Stop, etc.). They are powerful — they can block tool calls, run linters, or trigger external scripts — but they execute on the host machine without further confirmation. For ANCHOR, hooks must be added deliberately, one at a time, with founder approval.

## Status

- No hooks installed.
- No `.claude/settings.json` hooks block added by this scaffold.
- This README exists so the directory is discoverable for future opt-in additions.

## Candidate hooks (NOT installed — for future founder decision)

If you later want hooks, the following are the most defensible candidates. Each one must be explicitly approved before being wired into `.claude/settings.json` or `settings.local.json`.

1. **PostToolUse → `npm run lint`** (after `Edit`/`Write`).
   Rationale: hold the 0-error lint baseline. Risk: slow loops; ignores the existing acceptable AppShell custom-font warning unless filtered.

2. **PostToolUse → `npm run build`** (after `Edit`/`Write` on `app/**`, `pages/**`, `components/**`, `lib/**`).
   Rationale: catch type/runtime regressions early. Risk: very slow; better reserved for pre-commit or pre-PR.

3. **PreToolUse blocker on `Edit`/`Write` targeting `components/shell/AppShell.tsx`.**
   Rationale: enforces the "do not touch AppShell" doctrine line at the harness level. Risk: blocks even intentional, founder-approved edits — must include a clear bypass.

4. **PreToolUse blocker on `Edit`/`Write` targeting `docs/canonical/**`.**
   Rationale: canonical artefacts are owned by the founder; agents should not edit them silently. Risk: blocks legitimate reconciliation work by `anchor-docs-reconciler` unless that agent is allow-listed.

5. **PreToolUse warn on git commands containing `commit` or `push`.**
   Rationale: project rule is "do not commit or push unless explicitly asked". Risk: noisy; user must dismiss frequently.

6. **PostToolUse grep for forbidden wording** (after `Edit`/`Write` on `**/*.{tsx,ts,md,mdx}`).
   Rationale: catches "compliant", "certified", "RCVS-approved", present-tense "vendor-neutral", "chat history", "clinical record", "buyer discovery", etc., before they land. Risk: false positives in historical documents.

## How to add a hook (when approved)

1. Founder authorises the specific hook in writing.
2. Add an entry to `.claude/settings.json` under `hooks` (project-shared) or `.claude/settings.local.json` (machine-local; not committed).
3. Test on a throwaway change first.
4. Document the hook in this README — purpose, command, scope, bypass.

## What this directory must NOT contain

- Hooks that auto-commit or auto-push.
- Hooks that auto-fix the AppShell custom-font warning.
- Hooks that rewrite canonical documents without explicit instruction.
- Hooks that enable Workspace live-generation in production.
- Hooks that install third-party plugins or dependencies.
