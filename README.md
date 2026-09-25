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
  offered again. You see the offer too: at the end of a turn, one line on screen such as «2 observations on
  chrome-bridge ready to send: /chrome-bridge:observe send», once, then silence for seven days.
- **Security observations take a private path.** Claude marks a note `--security` when it saw a read or write outside
  the perimeter, a secret exposed, code run that was not asked for, or data leaving the computer (it decides from what
  it saw; it never asks you to classify), and `--severity high` when a defect of the plugin blocked the work (data
  lost, a wrong command run, a session lost). A security observation **never** enters the public issue: `observe send
  --security` prepares a separate anonymized report that only the maintainers read — a GitHub private vulnerability
  report, or the address in the plugin's SECURITY.md — again after your yes. Security and high observations are
  offered at once, sit on top of `list` and `export`, and the maintainer's own session sees their count first.

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
    "security": "advisory",
    "match": {"mcp": ["mcp__my-plugin__"], "bash": ["(^|\\s|/)my-plugin(\\s|$)"]},
    "benign_exits": {"check": [1]}, "known": []}
   ```

   `security` says where security observations go, and it is required for them to be sent: `advisory` is a GitHub
   private vulnerability report on `repo` (enable «Private vulnerability reporting» in the repository's security
   settings, `gh api -X PUT repos/<repo>/private-vulnerability-reporting`), otherwise a `mailto:` or a URL, the one in
   your SECURITY.md. Without it the report is refused and the user is told to ask you — never a public issue.
2. `python3 sync.py <plugin-root>`: copies `observe.py`, writes `observe/SOURCE`, adds the three hooks to
   `hooks/hooks.json` (PostToolUseFailure, SessionStart, Stop — the line on screen), and generates
   `commands/observe.md`, the `/<plugin>:observe send|send --security|list|mark|add` command, from the template in
   `commands/` (a hand-written one is left alone). Idempotent.
3. In the plugin's release script: `bash check.sh <plugin-root>` fails if the copy differs from the source.
4. Publish a SECURITY.md in the repository saying how to report privately (the advisory page, or the address).

`observe.py` needs only the Python standard library. Record format: [FORMAT.md](FORMAT.md).

## License

MIT
