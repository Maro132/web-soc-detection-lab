<?php
// 1. Extract path, method, and parameters
$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$responseBody = "";
$statusCode = 200;

// 2. Application Routing & Handlers
if ($requestPath === '/' || $requestPath === '/index.php') {
    // Check for Command Execution parameter simulation (?cmd= or ?ip=)
    if (isset($_GET['cmd'])) {
        $cmd = $_GET['cmd'];
        $statusCode = 200;
        // Mocking execution response for testing
        $responseBody = "<h1>Command Diagnostic Output</h1><pre>Executed: " . htmlspecialchars($cmd) . "\nResult: desktop-soc-host\\marwan (mock response)</pre>";
    } else {
        $statusCode = 200;
        $responseBody = "<h1>Web SOC Lab</h1><p>Web Application Threat Detection & Recon Monitoring Environment.</p>";
    }

} elseif ($requestPath === '/ping.php') {
    $host = $_GET['host'] ?? '127.0.0.1';
    $statusCode = 200;
    $responseBody = "<h1>Network Diagnostics Utility</h1><pre>PING " . htmlspecialchars($host) . " ... Success.</pre>";

} elseif ($requestPath === '/login.php') {
    if ($method === 'POST') {
        $username = $_POST['user'] ?? '';
        $password = $_POST['pass'] ?? '';

        if ($username === 'admin' && $password === 'SuperSecretPassword123!') {
            $statusCode = 200;
            $responseBody = json_encode(["status" => "success", "message" => "Login Successful!"]);
        } else {
            $statusCode = 401;
            $responseBody = json_encode(["status" => "error", "message" => "Invalid credentials."]);
        }
    } else {
        $statusCode = 200;
        $responseBody = '<form method="POST" action="/login.php">
            <input type="text" name="user" placeholder="Username" required><br>
            <input type="password" name="pass" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>';
    }

} elseif ($requestPath === '/admin-login-secret-page.php') {
    $statusCode = 403;
    $responseBody = "<h1>403 Forbidden</h1><p>Access Denied: Administrative Area.</p>";

} else {
    $statusCode = 404;
    $responseBody = "<h1>404 Not Found</h1><p>The requested URL was not found on this server.</p>";
}

http_response_code($statusCode);

// 3. Generate Apache Combined Log Format entry
$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$timestamp = date('d/M/Y:H:i:s O');
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$protocol = $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1';
$contentLength = strlen($responseBody);
$referer = $_SERVER['HTTP_REFERER'] ?? '-';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '-';

$logEntry = sprintf(
    '%s - - [%s] "%s %s %s" %d %d "%s" "%s"' . PHP_EOL,
    $ip,
    $timestamp,
    $method,
    $uri,
    $protocol,
    $statusCode,
    $contentLength,
    $referer,
    $userAgent
);

// 4. Append to access.log
$logFile = __DIR__ . '/access.log';
file_put_contents($logFile, $logEntry, FILE_APPEND);

echo $responseBody;
