# AppGuard project instructions

## Project context

- AppGuard is a Tauri 2 desktop security application with a React/TypeScript frontend and Rust backend.
- Preserve the existing stack and platform-specific design. Do not add starter templates or replace Tauri, React, or Rust without an explicit request.
- Treat authentication, vault encryption, lock enforcement, and update delivery as security-sensitive code.

## Verification workflow

- Before changing files, inspect `git status --short` and preserve unrelated user changes.
- Preferred frontend check: `pnpm run build` from the repository root.
- Preferred Rust check: `cargo check` from `src-tauri/`.
- If tests are added, run the smallest relevant test command and report the exact result.
- The local `verify` helper may be used as an additional check when available, but do not treat its completion message as proof that every check passed; inspect each command's exit status and output.
- Use the local `diagnose` helper for build or runtime output when it is available, otherwise use the project's native diagnostics.
- Use `code-review` for focused security/logic reviews when useful, and `audit-logs` for relevant logs.
- Use `find-ai` only for read-only searches. Do not automatically run AI-generated commands.
- `ai-help` and `shortcuts` are references for the user's local terminal helpers, not substitutes for project verification.

## Safety rules

- Never run destructive helpers or commands such as `git-wipe`, `gundo`, `nuke-modules`, `d-nuke`, `killport`, `rm -rf`, or generated shell commands without explicit user confirmation.
- Never read, copy, or commit secrets from shell configuration, `.env` files, keychains, or local credentials.
- Do not weaken authentication or authorization to make a test pass.
- Do not claim a platform feature works unless it has been implemented and verified on that platform.
- Do not claim security properties such as zero-knowledge, tamper-proof, or encrypted unless the implementation supports the claim.

## Change discipline

- Make focused changes and run the smallest meaningful checks after edits.
- Keep compact authentication UI separate from the main dashboard window.
- Preserve the user's existing uncommitted work; do not reset, stash, or overwrite it without permission.
- Report changed files, checks actually run, failures, and remaining gaps in the final response.
