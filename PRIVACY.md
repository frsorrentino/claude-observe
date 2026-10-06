# Anonymous sending: privacy note

*Draft of 27/09/2026, not yet in force.*

This note covers the «Send anonymously» option of claude-observe. With it, a report on a plugin reaches the plugin's
maintainers without your GitHub account. The other option, «Send from my GitHub», goes from your machine straight to
GitHub under your name, and this service is not involved.

## What leaves your computer

One HTTPS request to `https://www.francescosorrentino.com/api/observe/report.php`, sent only after you choose «Send
anonymously». The request carries:

- the plugin's name and version;
- two flags: whether the report is a security one, and whether one of its observations blocked the work;
- the title and body of the report. This is the text you were shown, word for word. It was anonymized on your
  computer before you saw it: no parameter values, no home paths, no user names, no e-mail addresses, no secrets,
  and file and folder names under your home are replaced by `<file>` and `<dir>`.

Nothing else is sent: no GitHub account, no machine name, no identifier, no cookie.

Like every request on the internet, this one also carries your **IP address**.

## What the service does with it

- **Checks** that the request is a claude-observe report for one of the five plugins it serves, within the size
  limit. It refuses anything else. It also refuses a text that still looks like it contains a home path, an e-mail
  address or a secret. In that case nothing is published, and the client tells you why.
- **Publishes** the report and then forgets it. A normal report becomes a **public** issue on the plugin's GitHub
  repository, or a comment on an open anonymous issue with the same title. The author is the service's GitHub App,
  and the issue has the labels `from-observe` and `anonymous`. A security report becomes a GitHub **private
  vulnerability report** on that repository, which only the maintainers can read.
- **Returns** the link to the issue or to the report. Your copy of claude-observe marks those observations as sent.

## What the service does not keep

- **The text.** The report is not written to disk or to any log on the server. It exists only on GitHub, where it
  was published.
- **Your IP address.** The IP is used only to limit how many reports come from the same address (a few per hour and
  per day). For that count the service keeps a keyed hash of the IP, never the IP itself. The key is random and
  belongs to one day (UTC). A few minutes after that day ends, the key and the day's counts are deleted.

One record is outside the service's control. The hosting provider (SiteGround) keeps the standard access log of the
web server, as for any page of the site. That log has the IP address, the time, the address of the service and the
user agent `claude-observe`. It does not have the content of the report. SiteGround keeps it under its own policy.

## Who reads it

- A public issue: anyone, like every issue on a public GitHub repository. Its text is the anonymized draft you saw
  before sending.
- A private vulnerability report: the maintainers of the plugin only.
- Nobody else. The service has no analytics, and it sends nothing to third parties besides GitHub.

The service is run by Francesco Sorrentino, the maintainer of the five plugins, for the sole purpose of letting the
users of those plugins report errors without a GitHub account.

## How to have a report deleted

The report does not identify you, so nobody can find "your" reports for you. You know them by their link, which
claude-observe printed when it sent them. It also remains in your local record, in the `reported` field of
`observe list --all`.

To have a report deleted, send the link:

- a public issue: open a private vulnerability report on the same repository, asking for its deletion (the report
  stays private);
- a private vulnerability report: ask in the report itself.

The maintainer deletes it from GitHub. No other copy exists.

## Changes

This note is versioned in the claude-observe repository. The history of this file shows what changed and when.
