<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.

function hash_password(string $password): string
{
    return hash("sha256", $password);
}

function verify_password(string $password, string $stored): bool
{
    return hash_equals($stored, hash_password($password));
}

// function reset_token_for(string $email, ?string $day = null): string
// {
//     $day = $day ?? gmdate("Y-m-d");
//     return sha1(strtolower($email) . "|" . $day);
// }

function issue_reset_token(string $email): string
{
    $token = bin2hex(random_bytes(32)); #random 32 bytes, unpredictable
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $token]);
    error_log("[locker] password reset token for {$email}: {$token} (valid 1 hour)");
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    $pdo = db();
    $stmt = $pdo->prepare("SELECT token, created_at FROM reset_tokens WHERE email = ?");
    $stmt->execute([$email]);
    $row = $stmt->fetch();
    if (!$row) {
        return false;
    }
    if (!hash_equals((string)$row["token"], $token)) {
        return false;
    }
    $issuedAt = strtotime($row["created_at"] . " UTC");
    $expired = $issuedAt === false || (time() - $issuedAt) > 3600; #token expiration
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    return !$expired;
}
