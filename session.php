<?php
// Enforce secure session configurations
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');

// Defense-in-depth headers
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'sha256-HzQPPbHuAriw45p1tlpnNLTghZmrEOpaoKyDTAbW1lY='; style-src 'self' https://cdn.jsdelivr.net 'unsafe-hashes' 'sha256-Qrs1JhQY5fb6iwstBgcIXjhdZ/e7yxmNmU8E2Ifk1B4=' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'sha256-+5n2pTHWH6ZsTWcOKWxVMSQ+q5DPpLW2CZUmyGYLyTw=' 'sha256-jr2YXew6AENYn9ISroxZn1czMRpaMaI7lmsVVCCyP0A=' 'sha256-ZCrPCeMXS6QuBl5axIbJe6G9JNeCzZFKZAh2er8qhco=' 'sha256-0OeSxcK7/u8ak11ZMif8axFWSVF30YBBDclW/RKAFeA='; img-src 'self' data:; font-src 'self' data:;");
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

session_start();
