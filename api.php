<?php
// Allow cross-origin requests and set JSON response type
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

// Read the incoming JSON stream
$inputData = json_decode(file_get_contents("php://input"));

if (!empty($inputData->url)) {
    $rawUrl = $inputData->url;
    
    // Fallback parsing if scheme is missing
    if (!preg_match("~^(?:f|ht)tps?://~i", $rawUrl)) {
        $rawUrl = "http://" . $rawUrl;
    }
    
    $parsedUrl = parse_url($rawUrl);
    $domain = isset($parsedUrl['host']) ? $parsedUrl['host'] : $rawUrl;
    
    // Server-Side Threat Intelligence Logic
    $suspiciousKeywords = ["verify", "login", "security", "account", "update", "banking", "wallet", "confirm", "auth", "signin", "password"];
    $suspiciousTlds = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".country"];
    
    $keywordMatches = [];
    foreach ($suspiciousKeywords as $kw) {
        if (stripos($rawUrl, $kw) !== false) {
            $keywordMatches[] = $kw;
        }
    }
    
    $tldRisk = false;
    foreach ($suspiciousTlds as $tld) {
        if (substr_compare($domain, $tld, -strlen($tld)) === 0) {
            $tldRisk = true;
            break;
        }
    }

    $isHttps = (isset($parsedUrl['scheme']) && strtolower($parsedUrl['scheme']) === 'https');
    $isIpAddress = preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $domain);
    $subdomainCount = max(0, count(explode('.', $domain)) - 2);
    
    // Construct the Feature Vector Response
    $responseData = [
        "rawUrl" => $rawUrl,
        "domain" => $domain,
        "urlLength" => strlen($rawUrl),
        "dotCount" => substr_count($rawUrl, '.'),
        "hyphenCount" => substr_count($rawUrl, '-'),
        "digitCount" => preg_match_all("/[0-9]/", $rawUrl),
        "specialCharCount" => preg_match_all("/[@%_=?&#]/", $rawUrl),
        "entropy" => 4.5, // Hardcoded for this example; requires a custom entropy function in PHP
        "subdomainCount" => $subdomainCount,
        "isHttps" => $isHttps,
        "isIpAddress" => $isIpAddress,
        "keywordMatches" => $keywordMatches,
        "closestBrand" => "paypal", // Simulated server-side homoglyph logic
        "isHomoglyph" => true,      // Simulated server-side homoglyph logic
        "tldRisk" => $tldRisk
    ];

    http_response_code(200);
    echo json_encode($responseData);
} else {
    http_response_code(400);
    echo json_encode(["message" => "Error: No target URL provided in payload."]);
}
?>