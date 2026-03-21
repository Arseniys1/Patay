<?php
header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$uri    = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$raw    = file_get_contents('php://input');
$body   = json_decode($raw, true) ?? [];

// Health
if ($uri === '/health') {
    echo json_encode(['status' => 'ok', 'backend' => 'apache']);
    exit;
}

// API
if (strpos($uri, '/api/') === 0) {
    echo json_encode([
        'backend' => 'apache',
        'method'  => $method,
        'path'    => $uri,
        'status'  => 'ok',
    ]);
    exit;
}

// Auth login
if ($uri === '/auth/login' && $method === 'POST') {
    $username = $body['username'] ?? 'anonymous';
    echo json_encode([
        'backend'   => 'apache',
        'token'     => "fake-jwt-for-{$username}",
        'expiresIn' => 3600,
    ]);
    exit;
}

// Auth catch-all
if (strpos($uri, '/auth/') === 0) {
    echo json_encode(['backend' => 'apache', 'authenticated' => true]);
    exit;
}

// Webhook
if (strpos($uri, '/webhook/') === 0) {
    echo json_encode(['backend' => 'apache', 'received' => true, 'path' => $uri]);
    exit;
}

// Static
if (strpos($uri, '/static/') === 0) {
    header('Content-Type: text/plain');
    echo 'static file content';
    exit;
}

// Home
if ($uri === '/') {
    header('Content-Type: text/html; charset=utf-8');
    echo '<html><body><h1>Apache Backend</h1><p>Encrypt Proxy test backend</p></body></html>';
    exit;
}

http_response_code(404);
echo json_encode(['backend' => 'apache', 'error' => 'not found']);
