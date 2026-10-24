# Authentication security fixes

Callback handling again reads PHP's `$_GET`, `$_POST`, and `$_REQUEST` superglobals. This includes OAuth 1 callbacks, OpenID callbacks, Apple names, X errors, and examples 06/07. Example diagnostic output remains intentional.

The default HTTP client now verifies TLS certificates and hostnames. Configure a valid CA bundle when a deployment previously depended on disabled verification.

OAuth state and OAuth 1 nonces use secure randomness, with a strong OpenSSL fallback on older PHP. OAuth state comparisons are exact and constant-time, and each state is consumed before token exchange. OAuth 1 HMAC-SHA1 signatures remain unchanged because they are part of the provider protocol.

Telegram supports two login flows through separate providers. `Telegram` uses OpenID Connect (Authorization Code + PKCE) with the Client ID and Client Secret from BotFather's Web Login settings; its state and nonce are compared in constant time and consumed on the callback, and its cached JWKS is refetched once when a signing key rotates. `TelegramWidget` keeps the legacy Login Widget flow using the bot username and bot token. The two flows use different credentials and callbacks, so they are separate providers rather than a configuration switch, following `Twitter`/`X` and `LinkedIn`/`LinkedInOpenID`.

The widget includes a fresh, session-bound `ha_state` in its callback URL. Valid signatures from another session, unsolicited callbacks, and consumed states are rejected. Existing callbacks generated before this update must restart login. Custom widget integrations must preserve the generated callback URL, including its query string. Signed timestamps must be recent and cannot be far in the future.

Steam discovery and API URLs use HTTPS, including requests carrying the API key.

OpenID discovery accepts public HTTP(S) destinations by default. Corporate authorities can opt into private destinations using exact origins and approved addresses/CIDRs:

```php
$config = [
    'callback' => 'https://app.corp.example/auth/callback',
    'openid_identifier' => 'https://sso.corp.example/openid',
    'openid_trusted_endpoints' => [
        ['origin' => 'https://sso.corp.example', 'addresses' => ['10.20.30.10/32']],
        ['origin' => 'https://discovery.corp.example:8443', 'addresses' => ['10.20.31.0/24']],
    ],
    'openid_cainfo' => '/etc/ssl/certs/corporate-ca.pem', // optional when already in system trust
    'openid_proxy' => 'http://proxy.corp.example:8080',   // optional
];
$adapter = new \Hybridauth\Provider\OpenID($config);
```

Rules trust all paths on the exact scheme, hostname and port; there are no wildcard hosts or implicit subdomains. IP literals and IPv6 CIDRs are supported. Every DNS answer must be public or match an approved range for that origin. Add each private discovery or verification origin separately. Each redirect, XRDS location and verification endpoint is checked independently; trusting one authority does not authorize other internal resources. Destinations remain pinned to the checked IP, and HTTPS downgrades remain forbidden. Internal trust does not disable TLS certificate or hostname verification. DNS resolution currently uses IPv4 records; IPv6 literals are supported.

Configured HTTP(S) proxies use cURL CONNECT tunnels to the checked destination IP, preserving the authority's original HTTP Host, TLS SNI and certificate hostname. The proxy must allow CONNECT to that numerical IP and port. Proxy-side DNS resolution is intentionally avoided; the application must be able to resolve the authority locally. Proxy support requires cURL 7.49 or newer, including when direct requests would otherwise use PHP streams. There is no fallback to unvalidated proxy-side destination selection. An HTTPS proxy's private CA bundle can be supplied with `openid_proxy` as an array: `['scheme' => 'https', 'host' => 'proxy.corp.example', 'port' => 8443, 'cainfo' => '/path/proxy-ca.pem']`. Proxy credentials can be supplied in the configured proxy URL or its `user`/`pass` array fields. Never build the allowlist or proxy configuration from callback parameters.

Direct LightOpenID users can pass the same trusted-endpoint rules as the third constructor argument, or set its `trustedEndpoints` property. Its existing second argument configures the trusted proxy, and `cainfo` configures the authority CA bundle.

Development dependencies require patched PHPUnit branches. The local lock resolves PHPUnit 12.5.40. PHPUnit 4/6 are no longer permitted because no fixed releases exist for the reported coverage-file deserialization advisory. As before, `composer.lock` is ignored by this library repository; `composer.json` records the minimum fixed versions.

Run `php vendor/bin/phpunit --do-not-cache-result` for the full suite. `tests/Security/AuthenticationSecurityTest.php` and `tests/Security/OpenIDSecurityTest.php` covers the callback fixes and security boundaries using synthetic identities and stubbed provider requests. `tests/Security/OpenIDTransportTest.php` exercises real pinned HTTP transports against an isolated local fixture. No real provider credentials are required.

Verification of the original security fixes: 107 tests and 332 assertions passed on Windows PHP 8.3 and Docker PHP 8.3. The corporate extension adds 12 tests covering private authorities, exact origins/CIDRs, DNS rebinding, real CONNECT proxies, proxy credential isolation, and corporate CA/hostname checks. The fresh Snyk Code scan still has the same 53 reports, with no new findings: only the reviewed test-runner behavior, example/installer diagnostics, and OAuth HMAC-SHA1 signature warning remain. No Snyk ignores were added.

The subsequent OAuth2 comparison fixes are documented in [OAUTH2_SECURITY.md](OAUTH2_SECURITY.md), including shared S256 PKCE, public clients, refresh authentication, request isolation, strict token validation and metadata. The expanded suite passes with 141 tests and 537 assertions on Windows and Docker.
