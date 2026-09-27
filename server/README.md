# The anonymous sending service

`report.php` receives one report already anonymized by `observe.py` (the «Send anonymously» option, FORMAT.md) and
publishes it with a GitHub App: a public issue labelled `from-observe` and `anonymous` on the plugin's repository, or a
comment on the open anonymous issue with the same title. A security report becomes a private vulnerability report,
never an issue. What it keeps and what it does not: [PRIVACY.md](../PRIVACY.md).

It runs on francescosorrentino.com (SiteGround, PHP 8.2 with curl and openssl) at
`https://francescosorrentino.com/api/observe/report.php`. It is one file with no dependencies.

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

## Setup

These steps are done once. Steps 1 and 3 need the maintainer's account; the rest can be done over SSH.

1. **The GitHub App.** Open https://github.com/settings/apps/new and fill in:
   - name: `claude-observe-reports`. Issues will show `claude-observe-reports[bot]` as their author.
   - homepage: `https://github.com/frsorrentino/claude-observe`;
   - Webhook: untick «Active»;
   - Repository permissions: **Issues: Read and write**. Metadata read-only is added by itself. Nothing else;
   - «Only on this account».

   Create the App and note the **App ID**. Then «Generate a private key» downloads a `.pem` file.
2. **Install it** (the App's page → «Install App») on `frsorrentino`, with «Only select repositories» set to the five
   repositories of `OBSERVE_REPOS`.
3. **Private vulnerability reporting.** Security reports need it on each repository:
   `gh api -X PUT repos/frsorrentino/<repo>/private-vulnerability-reporting`.
4. **The labels** on the five repositories:
   `gh label create from-observe --color 0e8a16 -d "Sent by claude-observe" -R frsorrentino/<repo>` and
   `gh label create anonymous --color c5def5 -d "Sent without the reporter's account" -R frsorrentino/<repo>`.
5. **The secrets on the server**, outside `public_html`. The ssh alias of the site's account is `ads-api`, and its
   home is `/home/<user>`.

   ```sh
   ssh ads-api 'mkdir -p ~/private/observe/state && chmod 700 ~/private ~/private/observe ~/private/observe/state'
   scp app.pem ads-api:private/observe/app.pem
   ssh ads-api 'chmod 600 ~/private/observe/app.pem && umask 077 && cat > ~/private/observe/config.php' <<'EOF'
   <?php
   return ['app_id' => 'APP_ID', 'private_key' => '/home/<user>/private/observe/app.pem',
           'state_dir' => '/home/<user>/private/observe/state'];
   EOF
   rm app.pem   # the key lives only on the server
   ```

   The service looks for the configuration at `$OBSERVE_CONFIG` first, then at `~/private/observe/config.php`. There
   `~` is the account's home, read with posix when PHP-FPM has no `HOME`.
6. **Deploy.** Copy `report.php` to the site repository as `api/observe/report.php`, and let the site's usual deploy
   (GitHub Actions) publish it. Then add a cron job in Site Tools (Devs → Cron Jobs), once a day after midnight UTC:
   `5 0 * * * php /home/<user>/www/francescosorrentino.com/public_html/api/observe/report.php purge`.
   The job deletes the previous day's counts and their key, even when no request comes.
7. **Check from outside:** `bash server/check-live.sh`. It must end with «all ok».

To revoke the service: delete the App, or uninstall it from a repository. The key on the server then stops working.
