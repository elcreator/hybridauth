<?php

namespace HybridauthTest\Adapter;

use Hybridauth\Exception\InvalidAccessTokenException;
use Hybridauth\Storage\StorageImpl;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/OAuth2Fixtures.php';

class OAuth2TokenTest extends TestCase
{
    private function adapter($http = null, $extra = [])
    {
        return new OAuth2Adapter(array_replace([
            'keys' => ['id' => 'demo', 'secret' => 'synthetic-secret'],
            'callback' => 'https://app.invalid/callback',
        ], $extra), $http ?: new OAuth2Http(), new StorageImpl());
    }

    public function testReplacingAccountDiscardsPreviousRefreshCapability(): void
    {
        $http = new OAuth2Http();
        $adapter = $this->adapter($http);
        $adapter->setAccessToken(['access_token' => 'account-A', 'refresh_token' => 'refresh-A']);
        $this->assertTrue($adapter->isRefreshTokenAvailable());
        $adapter->setAccessToken(['access_token' => 'account-B', 'expires_at' => time() - 1]);
        $this->assertFalse($adapter->isRefreshTokenAvailable());
        $this->assertNull($adapter->refreshAccessToken());
        $this->assertSame([], $http->requests);
        $this->assertSame('account-B', $adapter->getAccessToken()['access_token']);
    }

    public function testDisconnectClearsRefreshAndResourceCredentials(): void
    {
        $http = new OAuth2Http();
        $adapter = $this->adapter($http);
        $adapter->setAccessToken(['access_token' => 'account-A', 'refresh_token' => 'refresh-A']);
        $adapter->disconnect();
        $this->assertFalse($adapter->isRefreshTokenAvailable());
        $this->assertSame([], $adapter->getAccessToken());
        $adapter->apiRequest('me');
        $this->assertArrayNotHasKey('Authorization', $http->requests[0][3]);
    }

    public function testInvalidResponsesDoNotChangeTokenState(): void
    {
        $http = new OAuth2Http();
        $adapter = $this->adapter($http);
        $adapter->setAccessToken(['access_token' => 'original', 'refresh_token' => 'refresh-A']);
        $before = $adapter->getAccessToken();
        $cases = [
            '{}', '{"access_token":""}', '{"access_token":"   "}', '{"access_token":false}',
            '{"access_token":123}', '{"access_token":["nested"]}',
            '{"access_token":"new","error":"invalid_grant"}',
            '{"access_token":"new","expires_in":"soon"}',
            '{"access_token":"new","expires_in":-1}',
            '{"access_token":"new","expires_in":0.5}',
            '{"access_token":"new","expires_in":true}',
            '{"access_token":"new","expires_in":"999999999999999999999"}',
            '{"access_token":"new","expires":null}',
            '{"access_token":"new","refresh_token":[]}',
            '{"access_token":"new","token_type":[]}',
            '{"access_token":"new","scope":[]}',
        ];
        foreach ($cases as $response) {
            try { $adapter->accept($response); $this->fail('Invalid token response accepted: ' . $response); }
            catch (InvalidAccessTokenException $expected) { $this->assertSame($before, $adapter->getAccessToken()); }
        }
    }

    public function testDeclaredJsonNeverFallsBackToFormParsing(): void
    {
        $http = new OAuth2Http();
        $http->headers = ['Content-Type' => ['application/problem+json; charset=utf-8']];
        $adapter = $this->adapter($http);
        foreach (['access_token=synthetic', '{broken', '[]', 'null'] as $body) {
            try { $adapter->accept($body); $this->fail('Malformed JSON accepted.'); }
            catch (InvalidAccessTokenException $expected) { $this->assertSame([], $adapter->getAccessToken()); }
        }
    }

    public function testLegacyFormResponseAndExplicitFormatOverride(): void
    {
        $http = new OAuth2Http();
        $http->headers = ['content_type' => 'application/x-www-form-urlencoded'];
        $adapter = $this->adapter($http);
        $adapter->accept('access_token=synthetic&expires_in=3600&scope=read+only');
        $this->assertSame('synthetic', $adapter->getAccessToken()['access_token']);
        $this->assertSame('read only', $adapter->getAccessToken()['scope']);
        $http->headers = ['Content-Type' => 'text/plain'];
        $adapter = $this->adapter($http, ['token_response_format' => 'form']);
        $adapter->accept('access_token=legacy');
        $this->assertSame('legacy', $adapter->getAccessToken()['access_token']);
    }

    public function testLifetimeIsReplacedAndZeroLifetimeIsExposed(): void
    {
        $adapter = $this->adapter();
        $adapter->accept('{"access_token":"old","expires_in":3600}');
        $this->assertFalse($adapter->hasAccessTokenExpired());
        $adapter->accept('{"access_token":"new"}');
        $this->assertNull($adapter->hasAccessTokenExpired());
        $this->assertArrayNotHasKey('expires_at', $adapter->getAccessToken());
        $adapter->accept('{"access_token":"immediate","expires_in":0}');
        $this->assertSame(0, $adapter->getAccessToken()['expires_in']);
        $this->assertTrue($adapter->hasAccessTokenExpired());
        $expiry = time() + 60;
        $adapter->accept(json_encode(['access_token' => 'absolute', 'expires' => $expiry]));
        $this->assertSame($expiry, $adapter->getAccessToken()['expires_at']);
        $adapter->accept('{"access_token":"expired","expires":0}');
        $this->assertTrue($adapter->hasAccessTokenExpired());
    }

    public function testLegacyXmlIsExplicitAndCannotDeclareEntities(): void
    {
        $http = new OAuth2Http();
        $http->headers = ['Content-Type' => 'application/xml'];
        $xml = '<token><access_token>legacy-token</access_token><expires_in>60</expires_in></token>';
        try { $this->adapter($http)->accept($xml); $this->fail('Implicit XML token response accepted.'); }
        catch (InvalidAccessTokenException $expected) { $this->assertNotEmpty($expected->getMessage()); }
        $adapter = $this->adapter($http, ['token_response_format' => 'xml']);
        $adapter->accept($xml);
        $this->assertSame('legacy-token', $adapter->getAccessToken()['access_token']);
        $before = $adapter->getAccessToken();
        try {
            $adapter->accept('<!DOCTYPE token [<!ENTITY demo "synthetic">]><token><access_token>&demo;</access_token></token>');
            $this->fail('XML entity declaration accepted.');
        } catch (InvalidAccessTokenException $expected) { $this->assertSame($before, $adapter->getAccessToken()); }
    }

    public function testUnknownResponseFormatIsRejectedEvenForValidJson(): void
    {
        $adapter = $this->adapter(null, ['token_response_format' => 'unknown']);
        $this->expectException(InvalidAccessTokenException::class);
        $adapter->accept('{"access_token":"synthetic"}');
    }

    public function testRefreshRotationAndOmittedFieldsHaveExplicitSemantics(): void
    {
        $adapter = $this->adapter();
        $adapter->accept('{"access_token":"A","refresh_token":"refresh-A","scope":"read","expires_in":60}');
        $adapter->acceptRefresh('{"access_token":"B"}');
        $this->assertSame('refresh-A', $adapter->getAccessToken()['refresh_token']);
        $this->assertSame('read', $adapter->getAccessToken()['scope']);
        $this->assertArrayNotHasKey('expires_at', $adapter->getAccessToken());
        $adapter->acceptRefresh('{"access_token":"C","refresh_token":"refresh-C","scope":"limited"}');
        $this->assertSame('refresh-C', $adapter->getAccessToken()['refresh_token']);
        $adapter->accept('{"access_token":"another-account"}');
        $this->assertFalse($adapter->isRefreshTokenAvailable());
        $this->assertArrayNotHasKey('scope', $adapter->getAccessToken());
    }

    public function testTokenMetadataRoundTripsWithoutOverwritingCanonicalFields(): void
    {
        $adapter = $this->adapter();
        $adapter->accept('{"access_token":"A","scope":"read-only","instance_url":"https://instance.invalid","expires_at":1}');
        $tokens = $adapter->getAccessToken();
        $this->assertSame('read-only', $tokens['scope']);
        $this->assertSame('https://instance.invalid', $tokens['token_metadata']['instance_url']);
        $this->assertArrayNotHasKey('expires_at', $tokens);
        $adapter->setAccessToken($tokens);
        $this->assertSame($tokens, $adapter->getAccessToken());
    }
}
