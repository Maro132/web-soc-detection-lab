<?php
// 1. استخراج المسار ونوع الطلب (Method)
$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$responseBody = "";
$statusCode = 200;

// 2. معالجة المسارات والتحقق من تسجيل الدخول (Authentication Logic)
if ($requestPath === '/' || $requestPath === '/index.php') {
    $statusCode = 200;
    $responseBody = "<h1>Web SOC Lab</h1><p>Web Application Threat Detection & Recon Monitoring Environment.</p>";

} elseif ($requestPath === '/login.php') {
    if ($method === 'POST') {
        $username = $_POST['user'] ?? '';
        $password = $_POST['pass'] ?? '';

        // بيانات الاعتماد الصحيحة للاختبار
        if ($username === 'admin' && $password === 'SuperSecretPassword123!') {
            $statusCode = 200;
            $responseBody = json_encode(["status" => "success", "message" => "Login Successful! Welcome admin."]);
        } else {
            // إرجاع كود 401 Unauthorized عند فشل تسجيل الدخول
            $statusCode = 401;
            $responseBody = json_encode(["status" => "error", "message" => "Invalid credentials."]);
        }
    } else {
        // عرض صفحة الدخول البسيطة لطلبات GET
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

// 3. تعيين كود الاستجابة HTTP
http_response_code($statusCode);

// 4. توليد سجل التتبع بصيغة Apache Combined القياسية
$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$timestamp = date('d/M/Y:H:i:s O');
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$protocol = $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1';
$contentLength = strlen($responseBody);
$referer = $_SERVER['HTTP_REFERER'] ?? '-';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '-';

// Apache Combined Log Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
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

// 5. كتابة السجل في access.log
$logFile = __DIR__ . '/access.log';
file_put_contents($logFile, $logEntry, FILE_APPEND);

// 6. إرسال الاستجابة
echo $responseBody;
