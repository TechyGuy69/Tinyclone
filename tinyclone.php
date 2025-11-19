<?php
// tinyclone_fixed.php - All-in-one URL shortener (fixed to use ?r=alias so links work without rewrites)
// Drop into webroot and open in browser. Requirements: PHP 7+, PDO_SQLITE enabled.

session_start();
ini_set('display_errors', 1); error_reporting(E_ALL);

// -------- CONFIG --------
$config = [
    'admin_password' => 'adminpass',    // CHANGE THIS before deploying
    'sqlite_file' => __DIR__ . '/data.sqlite',
    'qr_provider' => 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=',
    'ip_geo_url' => 'https://ipapi.co/', 
    'alias_length' => 6,
    'allowed_alias_pattern' => '/^[a-zA-Z0-9_-]{3,64}$/',
];

// -------- BASE URL / SCRIPT PATH --------
$proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$scriptDir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF']), '/\\');
$scriptFile = basename(__FILE__); // e.g., tinyclone_fixed.php
$base_path = ($scriptDir === '/' || $scriptDir === '\\') ? '' : $scriptDir;
$base_url = rtrim($proto . $host . $base_path, '/');

// -------- HELPERS --------
function e($s){ return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }
function json_out($arr, $code = 200){ http_response_code($code); header('Content-Type: application/json'); echo json_encode($arr); exit; }
function csrf_token(){ if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(24)); return $_SESSION['csrf']; }
function csrf_check($t){ return !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $t ?? ''); }
function generate_alias($len = 6){
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $s = '';
    for ($i=0;$i<$len;$i++) $s .= $chars[random_int(0, strlen($chars)-1)];
    return $s;
}
function detect_device($ua){
    $ua = strtolower($ua ?? '');
    if (strpos($ua, 'mobile') !== false && strpos($ua, 'tablet') === false) return 'Mobile';
    if (strpos($ua, 'tablet') !== false || strpos($ua, 'ipad') !== false) return 'Tablet';
    return 'Desktop';
}
function geo_lookup($ip, $config){
    if (empty($ip) || in_array($ip, ['127.0.0.1','::1'])) return null;
    $url = rtrim($config['ip_geo_url'], '/') . '/' . $ip . '/json/';
    $opts = ['http' => ['timeout' => 2]];
    $context = stream_context_create($opts);
    $json = @file_get_contents($url, false, $context);
    if (!$json) return null;
    $data = json_decode($json, true);
    if (is_array($data) && !empty($data['country_name'])) return $data['country_name'];
    return null;
}
// Build a *guaranteed-working* short URL that uses the script and ?r=alias
function make_short_url($base_url, $scriptFile, $alias){
    return rtrim($base_url, '/') . '/' . $scriptFile . '?r=' . urlencode($alias);
}

// -------- DB (SQLite) --------
try {
    $pdo = new PDO('sqlite:' . $config['sqlite_file']);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("CREATE TABLE IF NOT EXISTS links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alias TEXT UNIQUE,
        url TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        visits INTEGER DEFAULT 0
    );");
    $pdo->exec("CREATE TABLE IF NOT EXISTS clicks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        link_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip TEXT,
        user_agent TEXT,
        referrer TEXT,
        country TEXT,
        device TEXT,
        FOREIGN KEY(link_id) REFERENCES links(id)
    );");
} catch (Exception $ex){
    die("DB error: " . e($ex->getMessage()));
}

// -------- ROUTING & HANDLERS --------
// API: ?api=1 accepts POST JSON body { url, alias (optional) }
if (isset($_GET['api']) && ($_GET['api'] == '1' || $_GET['api'] === 'true')) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_out(['error' => 'POST required'], 405);
    $body = json_decode(file_get_contents('php://input'), true);
    if (!$body || empty($body['url'])) json_out(['error' => 'Invalid request, provide url'], 400);
    $url = trim($body['url']);
    $alias = trim($body['alias'] ?? '');
    if (!filter_var($url, FILTER_VALIDATE_URL)) json_out(['error' => 'Invalid URL'], 400);

    if ($alias === '') {
        // generate unique alias
        do {
            $alias = generate_alias($config['alias_length']);
            $stmt = $pdo->prepare('SELECT id FROM links WHERE alias = ?'); $stmt->execute([$alias]);
        } while ($stmt->fetch());
    } else {
        if (!preg_match($config['allowed_alias_pattern'], $alias)) json_out(['error' => 'Invalid alias pattern'], 400);
        $stmt = $pdo->prepare('SELECT id FROM links WHERE alias = ?'); $stmt->execute([$alias]); if ($stmt->fetch()) json_out(['error' => 'Alias taken'], 409);
    }

    $stmt = $pdo->prepare('INSERT INTO links (alias, url) VALUES (?, ?)');
    try {
        $stmt->execute([$alias, $url]);
    } catch (Exception $e) {
        json_out(['error' => 'DB error: ' . $e->getMessage()], 500);
    }

    $short = make_short_url($base_url, $scriptFile, $alias);
    json_out(['short' => $short, 'alias' => $alias], 201);
}

// Redirect by query fallback: ?r=alias  (works without rewrites)
if (!empty($_GET['r'])) {
    $alias = trim($_GET['r']);
    $stmt = $pdo->prepare('SELECT * FROM links WHERE alias = ? LIMIT 1');
    $stmt->execute([$alias]);
    $link = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$link) { http_response_code(404); echo "<h2>404 - Not found</h2><p>Alias " . e($alias) . " not found.</p>"; exit; }

    // log click (best-effort)
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $ref = $_SERVER['HTTP_REFERER'] ?? null;
    $device = detect_device($ua);
    $country = @geo_lookup($ip, $config);
    try {
        $pdo->prepare('INSERT INTO clicks (link_id, ip, user_agent, referrer, country, device) VALUES (?, ?, ?, ?, ?, ?)')
            ->execute([$link['id'], $ip, $ua, $ref, $country, $device]);
        $pdo->prepare('UPDATE links SET visits = visits + 1 WHERE id = ?')->execute([$link['id']]);
    } catch (Exception $e) {
        // ignore logging errors
    }

    header('Location: ' . $link['url'], true, 302);
    exit;
}

// PATH_INFO style (tinyclone_fixed.php/alias) — works if AcceptPathInfo ON
if (!empty($_SERVER['PATH_INFO'])) {
    $alias = ltrim($_SERVER['PATH_INFO'], '/');
    if ($alias !== '') {
        $stmt = $pdo->prepare('SELECT * FROM links WHERE alias = ? LIMIT 1');
        $stmt->execute([$alias]);
        $link = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($link) {
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
            $ref = $_SERVER['HTTP_REFERER'] ?? null;
            $device = detect_device($ua);
            $country = @geo_lookup($ip, $config);
            try {
                $pdo->prepare('INSERT INTO clicks (link_id, ip, user_agent, referrer, country, device) VALUES (?, ?, ?, ?, ?, ?)')
                    ->execute([$link['id'], $ip, $ua, $ref, $country, $device]);
                $pdo->prepare('UPDATE links SET visits = visits + 1 WHERE id = ?')->execute([$link['id']]);
            } catch (Exception $e) { /* ignore */ }
            header('Location: ' . $link['url'], true, 302);
            exit;
        }
    }
}

// Admin login/logout
if (isset($_POST['admin_login'])) {
    if (($_POST['admin_password'] ?? '') === $config['admin_password']) {
        $_SESSION['admin'] = true;
        header('Location: ' . $_SERVER['PHP_SELF'] . '?admin=1');
        exit;
    } else {
        $admin_error = "Invalid password";
    }
}
if (!empty($_GET['logout'])) {
    session_unset(); session_destroy(); header('Location: ' . $_SERVER['PHP_SELF']); exit;
}

// Create short link (form)
$created_short = '';
$create_error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_short'])) {
    if (!csrf_check($_POST['csrf'] ?? '')) {
        $create_error = 'Invalid CSRF token';
    } else {
        $url = trim($_POST['url'] ?? '');
        $alias = trim($_POST['alias'] ?? '');
        if ($url === '') $create_error = 'Please provide a URL.';
        elseif (!filter_var($url, FILTER_VALIDATE_URL)) $create_error = 'Invalid URL.';
        else {
            if ($alias === '') {
                do {
                    $alias = generate_alias($config['alias_length']);
                    $stmt = $pdo->prepare('SELECT id FROM links WHERE alias = ?');
                    $stmt->execute([$alias]);
                    $exists = $stmt->fetch();
                } while ($exists);
            } else {
                if (!preg_match($config['allowed_alias_pattern'], $alias)) $create_error = 'Alias can only contain letters, numbers, underscore or hyphen (3-64 chars).';
                else {
                    $stmt = $pdo->prepare('SELECT id FROM links WHERE alias = ?'); $stmt->execute([$alias]);
                    if ($stmt->fetch()) $create_error = 'Alias already taken.';
                }
            }
            if (!$create_error) {
                $stmt = $pdo->prepare('INSERT INTO links (alias, url) VALUES (?, ?)');
                try {
                    $stmt->execute([$alias, $url]);
                    // IMPORTANT: build a short URL that ALWAYS WORKS (using this script + ?r=)
                    $created_short = make_short_url($base_url, $scriptFile, $alias);
                } catch (Exception $e) {
                    $create_error = 'DB error: ' . $e->getMessage();
                }
            }
        }
    }
}

// Admin dashboard
if (isset($_GET['admin']) && $_GET['admin'] == '1') {
    if (empty($_SESSION['admin'])) {
        // show login form
        ?>
        <!doctype html><html><head><meta charset="utf-8"><title>TinyClone Admin Login</title></head><body>
        <h2>Admin Login</h2>
        <?php if (!empty($admin_error)) echo '<div style="color:#900">'.e($admin_error).'</div>'; ?>
        <form method="post"><input type="password" name="admin_password" placeholder="Password" required><button type="submit" name="admin_login">Login</button></form>
        <p><a href="<?= e($_SERVER['PHP_SELF']) ?>">Back</a></p>
        </body></html>
        <?php
        exit;
    }

    // Delete action
    if (!empty($_GET['delete']) && preg_match('/^\d+$/', $_GET['delete'])) {
        $id = (int)$_GET['delete'];
        $pdo->prepare('DELETE FROM clicks WHERE link_id = ?')->execute([$id]);
        $pdo->prepare('DELETE FROM links WHERE id = ?')->execute([$id]);
        header('Location: ' . $_SERVER['PHP_SELF'] . '?admin=1'); exit;
    }

    // show dashboard
    $links = $pdo->query('SELECT * FROM links ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
    ?>
    <!doctype html><html><head><meta charset="utf-8"><title>TinyClone Admin</title></head>
    <body>
    <h2>Admin Dashboard</h2>
    <p><a href="<?= e($_SERVER['PHP_SELF']) ?>">Create</a> | <a href="<?= e($_SERVER['PHP_SELF']) ?>?logout=1">Logout</a></p>
    <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse">
        <thead><tr><th>ID</th><th>Alias</th><th>URL</th><th>Visits</th><th>QR</th><th>Actions</th></tr></thead>
        <tbody>
        <?php foreach($links as $l): ?>
            <tr>
                <td><?= e($l['id']) ?></td>
                <td><?= e($l['alias']) ?></td>
                <td style="max-width:480px;overflow:hidden;word-break:break-all"><?= e($l['url']) ?></td>
                <td><?= e($l['visits']) ?></td>
                <td><img src="<?= e($config['qr_provider'] . urlencode(make_short_url($base_url, $scriptFile, $l['alias']))) ?>" style="height:64px"></td>
                <td>
                    <a href="<?= e(make_short_url($base_url, $scriptFile, $l['alias'])) ?>" target="_blank">Open</a> |
                    <a href="<?= e($_SERVER['PHP_SELF'] . '?admin=1&view=' . $l['id']) ?>">View Clicks</a> |
                    <a href="<?= e($_SERVER['PHP_SELF'] . '?admin=1&delete=' . $l['id']) ?>" onclick="return confirm('Delete link and its clicks?')">Delete</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <?php
    if (!empty($_GET['view']) && preg_match('/^\d+$/', $_GET['view'])) {
        $lid = (int)$_GET['view'];
        $stmt = $pdo->prepare('SELECT * FROM clicks WHERE link_id = ? ORDER BY created_at DESC LIMIT 2000');
        $stmt->execute([$lid]);
        $clicks = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo "<h3>Clicks for link #".e($lid)."</h3>";
        echo "<table border='1' cellpadding='6' style='border-collapse:collapse'><tr><th>When</th><th>IP</th><th>Country</th><th>Device</th><th>User Agent</th><th>Referrer</th></tr>";
        foreach($clicks as $c){
            echo "<tr>";
            echo "<td>" . e($c['created_at']) . "</td>";
            echo "<td>" . e($c['ip']) . "</td>";
            echo "<td>" . e($c['country']) . "</td>";
            echo "<td>" . e($c['device']) . "</td>";
            echo "<td style='max-width:400px;overflow:hidden;word-break:break-all'>" . e($c['user_agent']) . "</td>";
            echo "<td style='max-width:400px;overflow:hidden;word-break:break-all'>" . e($c['referrer']) . "</td>";
            echo "</tr>";
        }
        echo "</table>";
    }
    ?>
    </body></html>
    <?php
    exit;
}

// -------- SHOW UI --------
$csrf = csrf_token();
?><!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TinyClone - URL Shortener</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;max-width:960px;margin:18px auto;padding:12px}
input,button,textarea{padding:9px;border-radius:6px;border:1px solid #ccc;font-size:14px}
button{background:#0b74de;color:#fff;border:none;cursor:pointer}
label{display:block;margin-top:10px}
.container{background:#fff;padding:16px;border-radius:8px;border:1px solid #eee}
.notice{background:#e8f7ff;padding:10px;border-radius:6px}
.err{background:#ffecec;padding:10px;border-radius:6px;color:#900}
.small{font-size:0.9rem;color:#666}
</style>
</head>
<body>
<div class="container">
    <h2>TinyClone — URL Shortener</h2>
    <p class="small">This version returns short URLs that point to this script with <code>?r=alias</code>, so no Apache rewrites are required. API: <code>?api=1</code>. Admin: <code>?admin=1</code></p>

    <?php if (!empty($create_error)): ?><div class="err"><?= e($create_error) ?></div><?php endif; ?>
    <?php if (!empty($created_short)): ?><div class="notice">Short URL created: <a href="<?= e($created_short) ?>" target="_blank"><?= e($created_short) ?></a>
        <div style="margin-top:8px">QR Code: <img src="<?= e($config['qr_provider'] . urlencode($created_short)) ?>" alt="QR"></div>
    </div><?php endif; ?>

    <form method="post">
        <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
        <label>Destination URL</label>
        <input type="url" name="url" required placeholder="https://example.com/very/long/page" style="width:100%">
        <label>Custom alias (optional)</label>
        <input type="text" name="alias" placeholder="my-custom-alias" style="width:50%">
        <div style="margin-top:10px"><button type="submit" name="create_short">Create Short Link</button> <a href="?admin=1" style="margin-left:10px">Admin Dashboard</a></div>
    </form>

    <hr>
    <h4 class="small">Quick API</h4>
    <p class="small">POST JSON to <code><?= e($_SERVER['PHP_SELF']) ?>?api=1</code> with body <code>{"url":"https://...","alias":"optional"}</code>. Response JSON: <code>{ "short":"...", "alias":"..." }</code></p>

    <p class="small">To test a short link without rewrites, open the returned short URL (which uses <code>?r=alias</code>), or manually open <code><?= e($scriptFile) ?>?r=alias</code>.</p>
</div>

<footer style="text-align:center;margin-top:14px" class="small">
    Data stored in <code><?= e(basename($config['sqlite_file'])) ?></code>. Change admin password in the config section at the top.
</footer>
</body>
</html>
