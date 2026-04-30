# Working rules for this repo

## Never delete on inference. Triple-confirm.

When the user asks a question about something on screen ("what is X?",
"why is X here?", "where did X go?") — that is **a question**, not a
request to delete or change it. Do not jump to "cutting it" or
"removing X" without an explicit instruction to do so.

If you think something should be removed, ask first. Three times if the
change is irreversible-feeling (UI element, public output, schema). The
user's pattern is to ask why something exists; if the explanation is
unsatisfying *they* will then tell you to delete it. Do not pre-empt.

This applies especially to:

- UI/output elements (columns, charts, headers, tables)
- README sections
- CLI flags
- Existing files in the repo

When in doubt: explain what the thing is, ask whether to keep / change /
remove. Wait for an explicit "delete it" / "yes" before touching code.
