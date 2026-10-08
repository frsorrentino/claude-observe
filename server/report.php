<?php
/**
 * claude-observe — the anonymous sending service (27/09/2026). One file, PHP 7.4+ with curl and openssl.
 *
 * Receives ONE report already anonymized by observe.py (`report --send HASH --anonymous`: plugin, version, security,
 * severity, title, body; FORMAT.md) and publishes it with the GitHub App of the service: a public issue with the labels
 * from-observe and anonymous (or a comment on the open anonymous issue with the same title), or, for a security report,
 * a private vulnerability report. Answers {"url": ...} or {"error": ...}. The privacy note is PRIVACY.md.
 *
 * What it never does: write the text anywhere (disk, log), keep an IP. The rate limit keeps an HMAC of the IP with a
 * key of the day (UTC); the day's file, key included, is deleted when the day ends (`php report.php purge` from cron,
 * and at every request).
 *
 * Configuration: a PHP file returning an array, OUTSIDE the document root, at $OBSERVE_CONFIG or
 * ~/private/observe/config.php (server/README.md). The service refuses to run (503) when the private key or the state
 * folder sit under the document root or are readable by others: on SiteGround Nginx serves static files without
 * Apache, so an .htaccess does not protect them.
 */

const OBSERVE_REPOS = [   // plugin → repository: the only destinations; anything else is refused
    'fable-director' => 'frsorrentino/fable-director',
    'claude-master' => 'frsorrentino/claude-master',
    'chrome-bridge' => 'frsorrentino/chrome-bridge',
    'claude-observe' => 'frsorrentino/claude-observe',
    'claude-master-watch' => 'frsorrentino/claude-master-watch',
    'team-supervisor' => 'frsorrentino/team-supervisor',   // claude-master's new name (07/10); both until the old one is gone
    'team-supervisor-app' => 'frsorrentino/team-supervisor-app',   // claude-master-watch's new name (07/10), same
    'supervisor' => 'frsorrentino/supervisor',   // team-supervisor's new name (08/10); both until the old one is gone
    'supervisor-app' => 'frsorrentino/supervisor-app',   // team-supervisor-app's new name (08/10), same
];
const OBSERVE_FIELDS = ['plugin', 'version', 'security', 'severity', 'title', 'body'];
const OBSERVE_MAX_BYTES = 65536;   // the draft is at most 20 rows of ~1.5 KB
const OBSERVE_LABELS = ['from-observe', 'anonymous'];
const OBSERVE_PRIVACY = 'https://github.com/frsorrentino/claude-observe/blob/main/PRIVACY.md';

class ObserveError extends Exception
{
    public $status;

    public function __construct($status, $message)
    {
        parent::__construct($message);
        $this->status = $status;
    }
}

function observe_home()
{
    $h = getenv('HOME');
    if (!$h && function_exists('posix_getpwuid')) {
        $h = posix_getpwuid(posix_geteuid())['dir'] ?? '';
    }
    return $h ?: sys_get_temp_dir();
}

function observe_config()
{
    $path = getenv('OBSERVE_CONFIG') ?: observe_home() . '/private/observe/config.php';
    if (!is_file($path)) {
        throw new ObserveError(503, 'the service is not configured');
    }
    $c = require $path;
    $c['config'] = $path;
    $c += ['github_api' => 'https://api.github.com', 'repos' => OBSERVE_REPOS, 'per_ip_hour' => 5, 'per_ip_day' => 10,
           'global_day' => 50, 'privacy' => OBSERVE_PRIVACY];
    foreach (['app_id', 'private_key', 'state_dir'] as $k) {
        if (empty($c[$k])) {
            throw new ObserveError(503, 'the service is not configured');
        }
    }
    return $c;
}

/** The secrets and the state must not be reachable from the web, nor readable by other users. */
function observe_check_placement($c)
{
    $root = realpath($_SERVER['DOCUMENT_ROOT'] ?? '') ?: '';
    foreach ([$c['private_key'], $c['state_dir'], $c['config']] as $p) {
        $real = $p ? realpath($p) : false;
        if ($p && $real === false) {
            throw new ObserveError(503, 'the service is misconfigured');
        }
        if ($real && $root && strpos($real . '/', rtrim($root, '/') . '/') === 0) {
            error_log('observe: a secret or the state folder is under the document root');
            throw new ObserveError(503, 'the service is misconfigured');
        }
    }
    if ((fileperms($c['private_key']) & 0077) || (fileperms($c['state_dir']) & 0077)) {
        error_log('observe: the private key must be 0600 and the state folder 0700');
        throw new ObserveError(503, 'the service is misconfigured');
    }
}

// ---------------------------------------------------------------------------------------------------- rate limit

/** Deletes the files of the days before today (UTC): the counts and the key that could link them to an IP. */
function observe_purge($dir)
{
    $today = 'rate-' . gmdate('Ymd') . '.json';
    foreach (glob(rtrim($dir, '/') . '/rate-*.json') ?: [] as $f) {
        if (basename($f) !== $today) {
            @unlink($f);
        }
    }
}

/** Counts this request for its IP (every POST, valid or not) and refuses beyond the limits. */
function observe_rate($c, $ip)
{
    $dir = rtrim($c['state_dir'], '/');
    $lock = fopen("$dir/.lock", 'c');
    if (!$lock || !flock($lock, LOCK_EX)) {
        throw new ObserveError(503, 'the service is busy, retry later');
    }
    try {
        observe_purge($dir);
        $file = "$dir/rate-" . gmdate('Ymd') . '.json';
        $s = is_file($file) ? json_decode((string)file_get_contents($file), true) : null;
        if (!is_array($s) || empty($s['key'])) {
            $s = ['key' => bin2hex(random_bytes(32)), 'ips' => [], 'published' => 0];
        }
        $id = hash_hmac('sha256', $ip, $s['key']);
        $now = time();
        $seen = $s['ips'][$id] ?? [];
        $hour = count(array_filter($seen, function ($t) use ($now) { return $t > $now - 3600; }));
        $refuse = count($seen) >= $c['per_ip_day'] || $hour >= $c['per_ip_hour'];
        if (!$refuse) {
            $seen[] = $now;
            $s['ips'][$id] = $seen;
        }
        $tmp = "$file.tmp";
        file_put_contents($tmp, json_encode($s));
        chmod($tmp, 0600);
        rename($tmp, $file);
        if ($refuse) {
            throw new ObserveError(429, 'too many reports from this address: retry in an hour, or tomorrow');
        }
        if ($s['published'] >= $c['global_day']) {
            throw new ObserveError(429, 'the service reached its daily limit: retry tomorrow');
        }
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function observe_count_published($c)
{
    $dir = rtrim($c['state_dir'], '/');
    $lock = fopen("$dir/.lock", 'c');
    flock($lock, LOCK_EX);
    $file = "$dir/rate-" . gmdate('Ymd') . '.json';
    $s = json_decode((string)@file_get_contents($file), true);
    if (is_array($s)) {
        $s['published'] = ($s['published'] ?? 0) + 1;
        file_put_contents("$file.tmp", json_encode($s));
        chmod("$file.tmp", 0600);
        rename("$file.tmp", $file);
    }
    flock($lock, LOCK_UN);
    fclose($lock);
}

// ---------------------------------------------------------------------------------------------------- validation

/** Only an observe draft (observe.py draft()) for a plugin of the allowlist; nothing else is published. */
function observe_validate($c, $raw)
{
    $r = json_decode($raw, true);
    if (!is_array($r) || array_keys($r) === range(0, count($r) - 1)) {
        throw new ObserveError(400, 'the request is not a JSON object');
    }
    $keys = array_keys($r);
    sort($keys);
    $want = OBSERVE_FIELDS;
    sort($want);
    if ($keys !== $want) {
        throw new ObserveError(400, 'the fields must be exactly: ' . implode(', ', OBSERVE_FIELDS));
    }
    if (!is_string($r['plugin']) || !isset($c['repos'][$r['plugin']])) {
        throw new ObserveError(400, 'this service accepts reports only for: ' . implode(', ', array_keys($c['repos'])));
    }
    if (!($r['version'] === null || (is_string($r['version']) && preg_match('/^[0-9A-Za-z.+-]{1,40}$/', $r['version'])))) {
        throw new ObserveError(400, 'version must be null or a version string');
    }
    if (!is_bool($r['security']) || !($r['severity'] === null || $r['severity'] === 'high')) {
        throw new ObserveError(400, 'security must be a boolean and severity null or "high"');
    }
    if (!is_string($r['title']) || !is_string($r['body']) || !mb_check_encoding($r['title'] . $r['body'], 'UTF-8')) {
        throw new ObserveError(400, 'title and body must be UTF-8 strings');
    }
    $p = preg_quote($r['plugin'], '/');
    $title_re = $r['security'] ? "/^\\[$p\\] security observation\\(s\\): \\d+$/u" : "/^\\[$p\\] field observations: /u";
    if (mb_strlen($r['title']) > 300 || strpos($r['title'], "\n") !== false || !preg_match($title_re, $r['title'])) {
        throw new ObserveError(400, 'the title is not the one of a claude-observe draft');
    }
    $lines = explode("\n", $r['body']);
    $head = $r['security'] ? '/^Private security report prepared on \d{4}-\d{2}-\d{2} by claude-observe /'
                           : '/^Collected on \d{4}-\d{2}-\d{2} by claude-observe /';
    if (count($lines) < 3 || !preg_match($head, $lines[0]) || $lines[1] !== '') {
        throw new ObserveError(400, 'the body is not the one of a claude-observe draft');
    }
    foreach (array_slice($lines, 2) as $l) {
        if (!preg_match('/^(- |  - (note|workaround): )/u', $l) || mb_strlen($l) > 2000) {
            throw new ObserveError(400, 'the body is not the one of a claude-observe draft');
        }
    }
    observe_screen($r['title'] . "\n" . $r['body']);
    return $r;
}

/** A second net behind the client's anonymizer: a text that still looks personal is refused, never published. */
function observe_screen($t)
{
    $checks = [
        'a home path' => '~(/home/|/Users/|\b[A-Za-z]:[\\\\/]+Users[\\\\/]+)(?!<|Shared\b|Public\b|Default\b)[^\s/\\\\<>`]+~i',
        'an e-mail address' => '/[\w.+-]+@[\w-]+\.[A-Za-z]{2,}/',
        'a secret' => '/(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|\bsk-[A-Za-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16}\b|'
                      . '\bxox[abprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY|\bAIza[0-9A-Za-z_-]{35})/',
    ];
    foreach ($checks as $what => $re) {
        if (preg_match($re, $t)) {
            throw new ObserveError(422, "the text still looks like it contains $what: nothing was published");
        }
    }
}

// ---------------------------------------------------------------------------------------------------- GitHub

function observe_b64url($s)
{
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}

function observe_jwt($c)
{
    $key = openssl_pkey_get_private((string)file_get_contents($c['private_key']));
    if (!$key) {
        throw new ObserveError(503, 'the service is misconfigured');
    }
    $now = time();
    $h = observe_b64url(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
    $p = observe_b64url(json_encode(['iat' => $now - 60, 'exp' => $now + 540, 'iss' => (string)$c['app_id']]));
    openssl_sign("$h.$p", $sig, $key, OPENSSL_ALGO_SHA256);
    return "$h.$p." . observe_b64url($sig);
}

/** One call to the GitHub API. Returns [status, decoded body]; never logs what it sends. */
function observe_gh($c, $method, $path, $auth, $data = null)
{
    $ch = curl_init(rtrim($c['github_api'], '/') . $path);
    $headers = ['Accept: application/vnd.github+json', 'X-GitHub-Api-Version: 2022-11-28', 'User-Agent: claude-observe-service',
                "Authorization: $auth"];
    if ($data !== null) {
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }
    curl_setopt_array($ch, [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => $headers, CURLOPT_RETURNTRANSFER => true,
                            CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_TIMEOUT => 25]);
    $out = curl_exec($ch);
    $status = $out === false ? 0 : curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return [$status, json_decode((string)$out, true)];
}

function observe_gh_ok($what, $res, $ok = [200, 201])
{
    if (!in_array($res[0], $ok, true)) {
        error_log("observe: GitHub answered {$res[0]} to $what");   // the status only, never the text
        throw new ObserveError(502, "GitHub refused the report ($what: {$res[0]}); nothing was published, retry later");
    }
    return $res[1];
}

/** An installation token limited to the destination repository, valid one hour, never stored. */
function observe_token($c, $repo)
{
    $jwt = 'Bearer ' . observe_jwt($c);
    $inst = observe_gh_ok('installation', observe_gh($c, 'GET', "/repos/$repo/installation", $jwt));
    $tok = observe_gh_ok('token', observe_gh($c, 'POST', "/app/installations/{$inst['id']}/access_tokens", $jwt,
                                             ['repositories' => [explode('/', $repo)[1]]]));
    return 'token ' . $tok['token'];
}

function observe_publish($c, $r)
{
    $repo = $c['repos'][$r['plugin']];
    $auth = observe_token($c, $repo);
    $foot = "\n\n---\nSent anonymously through the claude-observe service ([privacy]({$c['privacy']}))"
          . ($r['version'] ? "; {$r['plugin']} {$r['version']}" : '') . ($r['severity'] === 'high' ? '; severity: high' : '') . '.';
    if ($r['security']) {
        $data = ['summary' => $r['title'], 'description' => $r['body'] . $foot];
        if ($r['severity'] === 'high') {
            $data['severity'] = 'high';
        }
        $res = observe_gh_ok('private report', observe_gh($c, 'POST', "/repos/$repo/security-advisories/reports", $auth, $data));
        return $res['html_url'] ?? "https://github.com/$repo/security/advisories";
    }
    $open = observe_gh_ok('issue search', observe_gh($c, 'GET', "/repos/$repo/issues?state=open&per_page=100&labels="
                                                          . implode(',', OBSERVE_LABELS), $auth));
    foreach (is_array($open) ? $open : [] as $i) {
        if (($i['title'] ?? '') === $r['title'] && empty($i['pull_request'])) {
            $res = observe_gh_ok('comment', observe_gh($c, 'POST', "/repos/$repo/issues/{$i['number']}/comments", $auth,
                                                       ['body' => "**{$r['title']}**\n\n{$r['body']}$foot"]));
            return $res['html_url'] ?? $i['html_url'];
        }
    }
    $res = observe_gh_ok('issue', observe_gh($c, 'POST', "/repos/$repo/issues", $auth,
                                             ['title' => $r['title'], 'body' => $r['body'] . $foot, 'labels' => OBSERVE_LABELS]));
    return $res['html_url'];
}

// ---------------------------------------------------------------------------------------------------- entry point

function observe_answer($status, $data)
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
}

function observe_main()
{
    ini_set('display_errors', '0');
    try {
        $c = observe_config();
        observe_check_placement($c);
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if ($method === 'GET' || $method === 'HEAD') {
            observe_answer(200, ['service' => 'claude-observe anonymous reports', 'plugins' => array_keys($c['repos']),
                                 'privacy' => $c['privacy']]);
            return;
        }
        if ($method !== 'POST') {
            throw new ObserveError(405, 'only POST');
        }
        observe_rate($c, (string)($_SERVER['REMOTE_ADDR'] ?? ''));
        if (stripos((string)($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json') !== 0) {
            throw new ObserveError(415, 'the request must be application/json');
        }
        $raw = (string)file_get_contents('php://input', false, null, 0, OBSERVE_MAX_BYTES + 1);
        if (strlen($raw) > OBSERVE_MAX_BYTES) {
            throw new ObserveError(413, 'the report is larger than ' . OBSERVE_MAX_BYTES . ' bytes');
        }
        $r = observe_validate($c, $raw);
        $url = observe_publish($c, $r);
        observe_count_published($c);
        observe_answer(201, ['url' => $url]);
    } catch (ObserveError $e) {
        observe_answer($e->status, ['error' => $e->getMessage()]);
    } catch (Throwable $e) {
        error_log('observe: ' . get_class($e) . ' at line ' . $e->getLine());   // no message: it may quote the input
        observe_answer(500, ['error' => 'internal error; nothing was published']);
    }
}

if (PHP_SAPI === 'cli') {
    if (($argv[1] ?? '') === 'purge') {   // cron, once a day after midnight UTC
        observe_purge(observe_config()['state_dir']);
        exit(0);
    }
    fwrite(STDERR, "usage: php report.php purge\n");
    exit(2);
}
observe_main();
