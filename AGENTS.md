# trapkit: rules for code assistants

- The code comments are the documentation; there are no design docs. When
  code changes, keep the comments describing it true.
- Everything in English: code, comments, log messages, commit messages.
- No personal data in the repo (real names, e-mails, home directory paths,
  own network addresses); use made-up values.
- `src/tk.h` is the only public header. The engine has no user-facing
  surface (no ioctl, device node, or addresses/actions from userspace) and
  must not know a specific game; that belongs to application modules.
  Check: `grep -rn '#include' src` shows only kernel headers and this repo.
- Keep it simple: early returns, no wrappers for a single caller, no error
  handling for cases that cannot happen.
- `make` stays warning-clean. Loading needs root and an application module,
  so say what you verified (build, `grep`, `modinfo`) and what you did not;
  never claim runtime behaviour that was not run.
- Licence is `GPL-2.0-only` (`LICENSE`); do not add per-file license
  headers and do not touch `MODULE_LICENSE("GPL")`.
- Commit messages: English imperative subject without a trailing period,
  short body when not obvious, no `Co-Authored-By` or "Generated with..."
  lines. Work lands on `master`; the user decides commit boundaries.
