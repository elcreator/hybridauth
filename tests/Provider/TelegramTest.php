<?php

namespace HybridauthTest\Hybridauth\Provider;

use Hybridauth\Exception\InvalidAuthorizationStateException;
use Hybridauth\Exception\UnexpectedApiResponseException;
use Hybridauth\HttpClient\Curl;
use Hybridauth\HttpClient\Util;
use Hybridauth\Provider\Telegram;
use Hybridauth\Provider\TelegramWidget;
use Hybridauth\Storage\StorageImpl;
use PHPUnit\Framework\TestCase;

class TelegramHttp extends Curl
{
    public $requests = [];
    public $token = [];
    public $jwks = [];

    public function request($uri, $method = 'GET', $parameters = [], $headers = [], $multipart = false)
    {
        $this->requests[] = [$uri, $method, $parameters, $headers];
        return json_encode($uri === Telegram::JWKS_URL ? array_shift($this->jwks) : $this->token);
    }
    public function getResponseHttpCode() { return 200; }
    public function getResponseClientError() { return null; }
}

class TelegramOidc extends Telegram
{
    public $input = [];
    public function filterInput($type, $name, $filter = FILTER_DEFAULT, $options = 0)
    {
        return isset($this->input[$name]) ? $this->input[$name] : null;
    }
}

class TelegramTest extends TestCase
{
    private static $keys = [];
    private $redirects = [];

    protected function setUp(): void
    {
        Util::setRedirectHandler(function ($url) { $this->redirects[] = $url; });
    }

    protected function tearDown(): void
    {
        Util::setRedirectHandler(null);
    }

    private function key($kid)
    {
        if (!isset(self::$keys[$kid])) {
            self::$keys[$kid] = openssl_pkey_new(['config' => dirname(__DIR__) . '/Security/fixtures/openssl.cnf',
                'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        }
        return self::$keys[$kid];
    }

    private function b64($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function jwks($kid)
    {
        $rsa = openssl_pkey_get_details($this->key($kid))['rsa'];
        return ['keys' => [['kty' => 'RSA', 'kid' => $kid, 'n' => $this->b64($rsa['n']), 'e' => $this->b64($rsa['e'])]]];
    }

    private function idToken($kid, $claims)
    {
        $claims += ['iss' => Telegram::ISSUER, 'aud' => 'demo-client', 'sub' => '424242', 'exp' => time() + 300,
            'name' => 'Demo User', 'preferred_username' => 'demo_user'];
        $signed = $this->b64(json_encode(['alg' => 'RS256', 'kid' => $kid])) . '.' . $this->b64(json_encode($claims));
        openssl_sign($signed, $signature, $this->key($kid), OPENSSL_ALGO_SHA256);
        return $signed . '.' . $this->b64($signature);
    }

    private function adapter($http, $storage = null)
    {
        return new TelegramOidc(['callback' => 'https://app.invalid/callback',
            'keys' => ['id' => 'demo-client', 'secret' => 'demo-secret']], $http, $storage ?: new StorageImpl());
    }

    private function begin($adapter)
    {
        $adapter->authenticate();
        parse_str(parse_url(end($this->redirects), PHP_URL_QUERY), $query);
        return $query;
    }

    public function testOidcFlowValidatesTokenAndConsumesAttempt(): void
    {
        $http = new TelegramHttp();
        $adapter = $this->adapter($http);
        $query = $this->begin($adapter);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertSame('openid profile', $query['scope']);

        $http->jwks = [$this->jwks('k1')];
        $http->token = ['access_token' => 'synthetic', 'token_type' => 'Bearer', 'expires_in' => 300,
            'id_token' => $this->idToken('k1', ['nonce' => $query['nonce']])];
        $adapter->input = ['code' => 'demo-code', 'state' => $query['state']];
        $adapter->authenticate();

        list($uri, , $parameters, $headers) = $http->requests[0];
        $this->assertSame(Telegram::TOKEN_URL, $uri);
        $this->assertSame($query['code_challenge'], $this->b64(hash('sha256', $parameters['code_verifier'], true)));
        $this->assertSame('Basic ' . base64_encode('demo-client:demo-secret'), $headers['Authorization']);
        $this->assertTrue($adapter->isConnected());
        $this->assertSame('424242', $adapter->getUserProfile()->identifier);
        $this->assertSame('https://t.me/demo_user', $adapter->getUserProfile()->profileURL);

        $replay = $this->adapter($http);
        $replay->input = $adapter->input;
        $this->expectException(InvalidAuthorizationStateException::class);
        $replay->authenticate();
    }

    public function testWrongStateNeverReachesTokenEndpoint(): void
    {
        $http = new TelegramHttp();
        $storage = new StorageImpl();
        $adapter = $this->adapter($http, $storage);
        $this->begin($adapter);
        $this->assertNotNull($storage->get('TelegramOidc.pkce_code_verifier'));
        $adapter->input = ['code' => 'demo-code', 'state' => 'forged'];
        try { $adapter->authenticate(); $this->fail('Forged state accepted.'); }
        catch (InvalidAuthorizationStateException $expected) {
            $this->assertSame([], $http->requests);
            $this->assertNull($storage->get('TelegramOidc.pkce_code_verifier'));
            $this->assertFalse($adapter->isConnected());
        }
    }

    public function testNonceMismatchIsRejected(): void
    {
        $http = new TelegramHttp();
        $adapter = $this->adapter($http);
        $query = $this->begin($adapter);
        $http->jwks = [$this->jwks('k1')];
        $http->token = ['access_token' => 'synthetic', 'id_token' => $this->idToken('k1', ['nonce' => 'other'])];
        $adapter->input = ['code' => 'demo-code', 'state' => $query['state']];
        $this->expectException(UnexpectedApiResponseException::class);
        $this->expectExceptionMessage('nonce mismatch');
        $adapter->authenticate();
    }

    public function testRotatedSigningKeyIsRefetchedOnce(): void
    {
        $http = new TelegramHttp();
        $adapter = $this->adapter($http);
        $http->jwks = [$this->jwks('k1'), $this->jwks('k2')];
        $adapter->setAccessToken(['id_token' => $this->idToken('k1', [])]);
        $adapter->setAccessToken(['id_token' => $this->idToken('k2', ['sub' => 'rotated'])]);
        $this->assertSame('rotated', $adapter->getUserProfile()->identifier);
        $this->assertCount(2, $http->requests);
    }

    public function testWidgetFlowIsAvailableAsSeparateProvider(): void
    {
        $widget = new TelegramWidget(['callback' => 'https://app.invalid/callback',
            'keys' => ['id' => 'demo_bot', 'secret' => 'bot-token']], null, new StorageImpl());
        $this->assertFalse($widget->isConnected());
        $this->assertNotInstanceOf(Telegram::class, $widget);
    }
}
