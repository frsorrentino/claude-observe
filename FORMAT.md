# Record format (v1)

One file per plugin: `${XDG_STATE_HOME:-~/.local/state}/claude-observe/<plugin>.jsonl`, one JSON object per line,
mode 0600 in a 0700 folder.

**Lock.** A writer takes two locks, always in this order:

1. where the platform has `flock` (Linux, macOS from Python): an exclusive `flock` on `<dir>/.lock`. The first copies
   (up to source commit a787654) take only this one, so it keeps new and old copies apart while users update;
2. always: the directory `<plugin>.jsonl.lock`, created with `mkdir` (atomic on every system). A writer without
   `flock` (Node, Windows) takes only this one.

Then it reads the file, changes it, writes `<plugin>.jsonl.tmp`, renames it over the file, removes the lock directory
and releases `flock`. If a lock is busy, wait and retry (the Python copy waits up to 3 s in all, then gives up on that
record); a lock directory older than 10 s belongs to a dead process and may be removed. No deadlock is possible: a
writer holding only the directory never waits for `flock`. Never rewrite the file without the directory lock.

**Pending.** A writer that cannot get the lock in time does not drop the record: it appends ONE line to
`<plugin>.pending.jsonl` with a single `O_APPEND` write (atomic without a lock for lines this small):
`{"v": 1, "tool": …, "id": …, "fields": {…record fields…}, "example": {…} | null, "at": epoch}`. The next writer that
holds the lock renames the pending file aside, applies each line as if it had just been recorded, and deletes it after
the rewrite. Readers ignore fields they do not know; writers keep them. A writer that finds a record with a `v`
higher than its own does not rewrite the file.

| Field | Type | Meaning |
|---|---|---|
| `v` | int | format version, `1` |
| `id` | string | `<tool[:12]>-<sha256(tool + "\0" + key)[:8]>`: the same error is the same record |
| `tool` | string | plugin name (`tool.json` → `name`) |
| `source` | string | `hook-mcp`, `hook-bash`, `manual`, or another component (`relay`, `server`) |
| `kind` | string | `error` or `note` |
| `call` | string | the **full** MCP tool name as Claude Code shows it (`mcp__<server>__<tool>`, also when an MCP server writes the record itself), or the redacted command (`tool subcommand --flag <ARG>`) |
| `error` | string | the error, scrubbed (home as `~`, emails, URL queries, secrets, typed values removed), ≤ 300 chars |
| `key` | string | normalized `call` + " " + `error` (quoted strings → `<STR>`, paths → `<PATH>`, digits → `<N>`, spaces collapsed, ≤ 300 chars): the deduplication key; a server gets the same `id` as the hook only if its error text is the one Claude Code shows |
| `count` | int | how many times it happened |
| `first_seen`, `last_seen` | float | epoch seconds |
| `account` | string | basename of the Claude Code config folder (`.claude`, `.claude-work`…) |
| `project` | string | basename of the session's folder |
| `context` | object | `tool_version`, `claude_code`, `model`, `os`, `recent_tools` (names only) |
| `examples` | list | at most 3: `at`, `input_shape` (field names and text lengths, never values), `error_raw`, `session_id`, `duration_ms`, `context` |
| `workaround`, `class`, `note` | string | written by hand (`add --on`, `mark`): class `D` our defect, `L` someone else's limit, `S` the site's behaviour |
| `status` | string | `new`, `triaged`, `done`, `reported` |
| `fixed_in` | string | version that fixed it: never offered as an issue again |
| `reported` | string | issue URL, comment URL or prefilled link |
| `attribution` | string | `uncertain` when the plugin's command was not the last one of the line |
| `security` | bool | set by hand (`add --security`): a read or write outside the perimeter, a secret exposed, unwanted code execution, data leaving the computer — never part of a public issue, sent only through `report --security` |
| `severity` | string | `high`, set by hand (`add --severity high`): a defect of the plugin that blocks the work |

A component that writes without Python (for example an MCP server run without its plugin) follows the same rules:
same file, same `id` computation, `source` of its own, and never parameter values.

## When observations are offered for sending

Any session, at start, for a plugin with a `repo` in `tool.json`, when its unsent records (status not `done` or
`reported`, attribution not `uncertain`, no `fixed_in`) meet one of: count ≥ `propose_after` (3); oldest `first_seen`
at least `propose_after_days` days ago (3; `0` = never by age); or a record with `class` `D` (a defect written by hand),
at once; a record with `security` or `severity` `high` also at once. Then not again for `propose_every_days` days (7)
for that plugin — `.proposed-<plugin>` (and `.proposed-sec-<plugin>` for the private path) in the state folder holds
the time — and never in the maintainer's own session. The same rule shows the user one line on screen at the end of a
turn (the Stop hook, `.shown-<plugin>` / `.shown-sec-<plugin>`), once per `propose_every_days`.

## The private path

Records with `security` never enter the public issue (`pending` excludes them). `report --security` (the command
`/<plugin>:observe send --security`) drafts one anonymized report of them, shows it, and sends it only with the user's
yes to the channel `tool.json` → `security` names: `advisory` = `POST /repos/<repo>/security-advisories/reports`
through `gh` (the repository needs «Private vulnerability reporting» on), or without `gh` the page
`https://github.com/<repo>/security/advisories/new` to paste the text into; a `mailto:` or URL = printed with the
text. Sent records get `status` `reported` and `reported` = the advisory URL or the address. No channel: refused.

## The anonymous path

`report --send HASH --anonymous` (the «Send anonymously» button) does one `POST` to `observe.endpoint` (config; empty =
the option is not offered) with `Content-Type: application/json` and exactly these fields: `plugin`, `version` (the
plugin's, or null), `security` (bool), `severity` (`high` or null), `title` and `body` — the anonymized draft, nothing
else. The service answers JSON with `url` (the issue it opened); the records are marked `reported` with it. `report
--later` («Not now») silences both offers for `propose_every_days`.
