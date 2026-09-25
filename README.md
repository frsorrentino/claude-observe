# claude-observe

Automatic, local collection of the errors a Claude Code plugin runs into, so the people who maintain it hear about
them without anyone having to remember to report them. It ships **inside** each plugin that uses it: one source (this
repo), one copy per plugin, checked by hash at every release of that plugin.

## What it does

- A `PostToolUseFailure` hook records the errors of **this plugin's own** calls only: its MCP tools (`isError`) and its
  commands in Bash (non-zero exit, except the codes the plugin documents as normal).
- Records go to a **local** file, `${XDG_STATE_HOME:-~/.local/state}/claude-observe/<plugin>.jsonl` (0600). The same
  error seen again is one record with a count.
- Of the tool parameters only **field names and text lengths** are kept, never values; commands pass a redactor;
  error texts are scrubbed (home path, emails, URL queries, secrets, typed values).
- When a known error comes back, the hook hands Claude the recorded workaround, or «fixed in X: update» when the
  installed version is older.
- **Nothing leaves the computer** unless you say yes: at a natural moment Claude offers to send the collected errors as
  **one** GitHub issue per plugin (or a comment on an open issue about the same error), shows the anonymized text, and
  sends it only after your confirmation — with `gh`, or as a prefilled link you open yourself. What was sent is never
  offered again.

Turn it off: `{"enabled": false}` in `~/.config/claude-observe/config.json`. Stop the offers only: `{"propose": false}`.

When the offer comes (config keys in `~/.config/claude-observe/config.json`): at the start of any session, for a plugin
whose unsent observations meet one of three conditions — they are at least `propose_after` (3); or the oldest of them has
waited at least `propose_after_days` days (3; `0` never counts age), so one or two observations are not forgotten for
ever; or one of them is marked class `D`, a defect of the plugin, which is offered at once. Between two offers for the
same plugin at least `propose_every_days` days (7) pass, and the session that maintains the plugin is never asked.

## For plugin maintainers

1. Add `<plugin-root>/observe/tool.json`:

   ```json
   {"name": "my-plugin", "repo": "me/my-plugin", "version_from": ".claude-plugin/plugin.json",
    "match": {"mcp": ["mcp__my-plugin__"], "bash": ["(^|\\s|/)my-plugin(\\s|$)"]},
    "benign_exits": {"check": [1]}, "known": []}
   ```

2. `python3 sync.py <plugin-root>`: copies `observe.py`, writes `observe/SOURCE`, adds the two hooks to
   `hooks/hooks.json` (idempotent).
3. In the plugin's release script: `bash check.sh <plugin-root>` fails if the copy differs from the source.

`observe.py` needs only the Python standard library. Record format: [FORMAT.md](FORMAT.md).

## License

MIT
