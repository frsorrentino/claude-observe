# The anonymous sending service

`report.php` receives one report already anonymized by `observe.py` (the «Send anonymously» option, FORMAT.md) and
publishes it with a GitHub App: a public issue labelled `from-observe` and `anonymous` on the plugin's repository, or a
comment on the open anonymous issue with the same title. A security report becomes a private vulnerability report,
never an issue. What it keeps and what it does not: [PRIVACY.md](../PRIVACY.md).

It runs on www.francescosorrentino.com (SiteGround, PHP 8.2 with curl and openssl) at
`https://www.francescosorrentino.com/api/observe/report.php`. It is one file with no dependencies. Without `www` the site
answers 301, and a redirected POST becomes a GET: clients must use the `www` URL.

What it checks, in this order:

1. The placement. The private key, the configuration and the state folder must sit outside the document root, the
   key 0600 and the folder 0700; otherwise it answers 503 and publishes nothing.
2. The per-IP limit: 5 POSTs an hour, 10 a day. Every POST counts, valid or not.
3. The format: JSON, at most 64 KB, and exactly the six fields.
4. The destination. The plugin must be in the allowlist (`OBSERVE_REPOS`). The title and body must have the shape of an
   observe draft.
5. The text. A text that still looks like it has a home path, an e-mail address or a secret gets 422.
6. The service's daily limit: 50 published reports.

The tests are in `tests/server-verify.py`. They run with php and openssl against a fake GitHub, with no network.

## Go-live checklist

Tick each box when it is done and verified. Steps 1-4 need the maintainer's own account. Steps a-h run from a Claude
session, only after the maintainer's ok, because each one writes outside this repository.

**The maintainer**

- [x] 1. **Create the GitHub App.** Open https://github.com/settings/apps/new and fill in:
  - name: `claude-observe-reports`. Issues will show `claude-observe-reports[bot]` as their author.
  - Homepage URL: `https://github.com/frsorrentino/claude-observe`;
  - Webhook: untick «Active»;
  - Repository permissions: **Issues: Read and write**. Metadata read-only is added by itself;
  - «Only on this account».

  Then «Create GitHub App». Note the **App ID**. «Generate a private key» downloads a `.pem` file.
- [x] 2. **Install the App.** On the App's page, «Install App» → `frsorrentino` → «Only select repositories», and
  pick the five repositories of `OBSERVE_REPOS`: fable-director, claude-master, chrome-bridge, claude-observe and
  claude-master-watch.
- [x] 3. **Hand over** the App ID and the local path of the `.pem`. Keep the `.pem` out of every repository.
- [x] 4. **Optional: the permission for security reports.** GitHub does not document which permission an App needs to
  file a private vulnerability report. If step g gets 403 on it, add «Repository security advisories: Read and
  write» to the App and approve the change on the installation. Adding it now saves that round.

**The session, after the ok**

- [x] a. **Private vulnerability reporting** on the repositories that do not have it yet. On 27/09 these were
  claude-observe and claude-master-watch: `gh api -X PUT repos/frsorrentino/<repo>/private-vulnerability-reporting`.
  Check all five with `gh api repos/frsorrentino/<repo>/private-vulnerability-reporting --jq .enabled`.
- [x] b. **The labels** on the five repositories:
  `gh label create from-observe --color 0e8a16 -d "Sent by claude-observe" -R frsorrentino/<repo>` and
  `gh label create anonymous --color c5def5 -d "Sent without the reporter's account" -R frsorrentino/<repo>`.
- [x] c. **The secrets on the server**, outside `public_html`. The ssh alias of the site's account is `ads-api`, and its
  home is `/home/<user>`.

  ```sh
  ssh ads-api 'mkdir -p ~/private/observe/state && chmod 700 ~/private ~/private/observe ~/private/observe/state'
  scp app.pem ads-api:private/observe/app.pem
  ssh ads-api 'chmod 600 ~/private/observe/app.pem && umask 077 && cat > ~/private/observe/config.php' <<'EOF'
  <?php
  return ['app_id' => 'APP_ID', 'private_key' => '/home/<user>/private/observe/app.pem',
          'state_dir' => '/home/<user>/private/observe/state'];
  EOF
  ssh ads-api 'ls -la ~/private/observe'   # app.pem -rw-------, state drwx------
  rm app.pem                               # the key lives only on the server
  ```

  The service reads its configuration from `$OBSERVE_CONFIG` or `~/private/observe/config.php`, where `~` is the
  account's home (read with posix when PHP-FPM has no `HOME`).
- [x] d. **Deploy.** Copy `server/report.php` to the site repository as `api/observe/report.php`. Commit that file only:
  the site repository may hold other people's work in progress. The push starts the production deploy (GitHub Actions
  → rsync).
- [ ] e. **The purge cron.** The maintainer adds it in Site Tools → Devs → Cron Jobs, once a day after midnight UTC:
  `5 0 * * * php /home/<user>/www/francescosorrentino.com/public_html/api/observe/report.php purge`.
  It deletes the previous day's counts and their key even when no request comes.
  *06/10: waiting for the maintainer (Site Tools needs their login). The command, run by hand over ssh, exits 0.*
- [x] f. **Check from outside:** `bash server/check-live.sh` must end with «all ok». If curl fails on TLS while the
  origin is healthy, it is the SiteGround CDN (see the site's notes).
- [ ] g. **End to end.** Set `{"endpoint": "https://www.francescosorrentino.com/api/observe/report.php"}` in
  `~/.config/claude-observe/config.json`. Then send one report per plugin with «Send anonymously»: from Linux, and
  from the `wincompat` session on Windows. Include one `--security` report. Each public issue must arrive with the
  labels `from-observe` and `anonymous` and the «Sent anonymously» line. The security one must arrive as a private
  report and not as an issue. The `segnalazioni.py` cron must announce the issues on Telegram. Close the test issues
  afterwards.
  *06/10, from Linux: five issues and one private report (GHSA on claude-observe), all as expected and all
  closed. `segnalazioni.py` skipped authors ending in `[bot]`; with `claude-observe-reports[bot]` let through, the cron
  of 23:10 announced all five. Still open: the Windows test, set for 07/10 with a `wincompat` session.*
- [x] h. **Turn it on in the client** (a separate commit, only after g). Put the URL as the default of
  `observe.endpoint`. Offer the option only for the plugins of the allowlist, so that a copy in a plugin outside it
  (pixelfarm) never offers a service that would refuse it. Update the README and the command template, which today
  say «coming», and update test OB40. Then publish PRIVACY.md and the release, with the maintainer's final ok.

**Adding a plugin** (07/10: `team-supervisor`, claude-master's new name; keep the old name until it is gone
everywhere). Add it to `OBSERVE_REPOS` and to `ANON_TOOLS` in `observe.py` (OB40 checks they match). Once the
repository exists, add it to the App's installation, then run steps a and b on it, deploy as in step d, and run step f.

To revoke the service: delete the App, or uninstall it from a repository. The key on the server then stops working.
