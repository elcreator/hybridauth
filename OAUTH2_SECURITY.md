# OAuth2 security and correctness

OAuth2 requests no longer inherit another request's bearer headers, JSON encoding, HTTP method, body or response headers. This applies to the default cURL client and to header isolation in the optional Guzzle client. Explicitly configured client defaults remain persistent.

Replacing an adapter's tokens discards the previous account's derived refresh parameters. Disconnect clears resource credentials and refresh capability. Token responses are validated before changing stored tokens: access tokens must be nonempty strings, lifetime fields must be nonnegative integers within the platform's timestamp range, and OAuth errors are rejected even on successful HTTP responses. Exceptions from this validation do not include the raw token response.

A new authorization response discards an old refresh token when no replacement is supplied. A refresh response may omit its refresh token, retaining the current one; a supplied replacement rotates it. Missing expiry means unknown lifetime rather than inheriting an earlier token's expiry. The legacy field `expires` (Facebook, Deezer) is read as a relative lifetime in seconds when `expires_in` is absent; `expires=0` means the token does not expire. Fields returned as `null` are treated as omitted. A `scope` returned as an array of strings (Twitch) is stored space-separated.

## S256 PKCE

Enable PKCE for a confidential client when its authority supports S256:

```php
$config = [
    'callback' => 'https://app.example/auth/callback',
    'keys' => ['id' => 'registered-client-id', 'secret' => 'registered-client-secret'],
    'pkce' => 'S256',
];
```

X enables S256 automatically. Other confidential-client adapters retain their provider-compatible default until PKCE is configured. Only S256 is supported; a configured requirement never falls back to plain or an exchange without a verifier. PKCE requires state validation. Each authorization attempt creates a fresh verifier and generated state, stores them in the adapter's storage, and consumes them during the callback. Reconstruct the callback adapter with the same provider configuration and session storage. A new attempt supersedes an earlier outstanding attempt for that provider/session. Explicit caller-supplied state remains supported; the caller must generate a fresh value for each attempt.

X callbacks started before this change must restart authorization because the previous verifier storage format has been replaced. Failed exchanges also require a new attempt.

Authorization URLs preserve existing queries and fragments. Array scopes are joined with spaces; provider-specific scope strings remain unchanged.

## Token endpoint client authentication

Code exchange and refresh share `token_endpoint_auth_method`:

| Method | Behavior |
| --- | --- |
| `client_secret_post` | Send the registered client ID and secret in the token request parameters. This remains the base adapter default. |
| `client_secret_basic` | Send form-encoded credentials in HTTP Basic authentication and remove them from the request body. |
| `none` | Send the client ID without a secret or Authorization header. S256 PKCE and state validation are mandatory. |

Authentiq, PayPal, Pinterest, Reddit, X and Yahoo select Basic authentication by default. Provider configuration may explicitly override the method to match the authority's registration. Existing custom Basic headers are respected without duplicating body credentials. WeChat keeps its provider-specific `appid` and `secret` parameters unless an authentication method is explicitly configured.

A public client needs no secret:

```php
$config = [
    'callback' => 'https://app.example/auth/callback',
    'keys' => ['id' => 'registered-public-client-id'],
    'token_endpoint_auth_method' => 'none',
];
```

The authority must support public clients and S256 for that registration. Setting `pkce` or state validation to false in this mode is rejected.

## Response formats and metadata

The default `token_response_format` is `auto`: JSON and legacy form responses are accepted. A response declaring JSON must contain a valid JSON object and cannot fall back to form parsing. Undeclared JSON is recognized by its opening delimiter. Nonstandard form responses with incorrect media types require explicit `token_response_format => 'form'`; adapters for such providers declare this default themselves (QQ), and configuration still overrides it. Legacy XML requires `token_response_format => 'xml'`; document type and entity declarations are rejected. `json` can be selected to require JSON even without a correct media type.

`getAccessToken()` now includes the provider's returned `scope` and a `token_metadata` array of additional response fields. These fields round-trip through `setAccessToken()`. Metadata cannot overwrite canonical token or expiry fields. During refresh, an omitted scope retains the current grant's scope; a new authorization response clears old scope when none is returned. Granted scopes describe provider output and do not replace resource-server permission checks.

## Verification

Run `php vendor/bin/phpunit --do-not-cache-result`. The OAuth2 regression tests cover request isolation, token/account replacement, rotation, malformed responses, lifetime handling, PKCE callback reconstruction and consumption, authorization URLs, public clients, and provider authentication compatibility. HTTP fixtures and tokens are synthetic; no provider account or project API key is needed.

The full suite passes on Windows PHP 8.3 and Docker PHP 8.3: 141 tests and 537 assertions. Twelve comparison probes also produce identical results on both platforms. Live authorization with external providers was not exercised.

A fresh Snyk Code scan reports the same 53 previously reviewed findings with no new findings or ignores: 44 refer to PHP's standalone test runner, eight to example/installer diagnostics, and one to the protocol-required OAuth 1 HMAC-SHA1 signature. These findings were compared by identity against the prior scan; they are not presented as a clean scanner result.
