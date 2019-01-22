<?php

namespace Trikoder\Bundle\OAuth2Bundle\Tests\Acceptance;

use Symfony\Component\HttpFoundation\Response;
use Trikoder\Bundle\OAuth2Bundle\Manager\AccessTokenManagerInterface;
use Trikoder\Bundle\OAuth2Bundle\Manager\RefreshTokenManagerInterface;
use Trikoder\Bundle\OAuth2Bundle\OAuth2TokenTypeHints;
use Trikoder\Bundle\OAuth2Bundle\Tests\Fixtures\FixtureFactory;
use Trikoder\Bundle\OAuth2Bundle\Tests\TestHelper;

final class IntrospectionEndpointTest extends AbstractAcceptanceTest
{
    public function testActiveAccessToken()
    {
        $response = $this->handleIntrospectionRequest([
            'token' => $this->getAccessToken(FixtureFactory::FIXTURE_ACCESS_TOKEN_USER_BOUND),
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        $jsonResponse = json_decode($response->getContent(), true);

        $this->assertTrue($jsonResponse['active']);
        $this->assertSame('foo', $jsonResponse['client_id']);
        $this->assertSame('bearer', $jsonResponse['token_type']);
        $this->assertSame(FixtureFactory::FIXTURE_ACCESS_TOKEN_USER_BOUND, $jsonResponse['jti']);
        $this->assertSame('user', $jsonResponse['sub']);
        $this->assertArrayNotHasKey('scope', $jsonResponse);
    }

    public function testActiveRefreshToken()
    {
        $response = $this->handleIntrospectionRequest([
            'token' => $this->getRefreshToken(FixtureFactory::FIXTURE_REFRESH_TOKEN),
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        $jsonResponse = json_decode($response->getContent(), true);

        $this->assertTrue($jsonResponse['active']);
        $this->assertSame('foo', $jsonResponse['client_id']);
        $this->assertSame('bearer', $jsonResponse['token_type']);
        $this->assertSame(FixtureFactory::FIXTURE_REFRESH_TOKEN, $jsonResponse['jti']);
    }

    public function testActiveTokenWitScopes()
    {
        $response = $this->handleIntrospectionRequest([
            'token' => $this->getAccessToken(FixtureFactory::FIXTURE_ACCESS_TOKEN_USER_BOUND_WITH_SCOPES),
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        $jsonResponse = json_decode($response->getContent(), true);

        $this->assertTrue($jsonResponse['active']);
        $this->assertSame('foo', $jsonResponse['client_id']);
        $this->assertSame('bearer', $jsonResponse['token_type']);
        $this->assertSame(FixtureFactory::FIXTURE_ACCESS_TOKEN_USER_BOUND_WITH_SCOPES, $jsonResponse['jti']);
        $this->assertSame('user', $jsonResponse['sub']);
        $this->assertSame('fancy', $jsonResponse['scope']);
    }

    public function testActiveTokenWithValidHint()
    {
        $response = $this->handleIntrospectionRequest([
            'token' => $this->getRefreshToken(FixtureFactory::FIXTURE_REFRESH_TOKEN),
            'token_hint' => OAuth2TokenTypeHints::REFRESH_TOKEN,
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        $jsonResponse = json_decode($response->getContent(), true);

        $this->assertTrue($jsonResponse['active']);
        $this->assertSame('foo', $jsonResponse['client_id']);
        $this->assertSame('bearer', $jsonResponse['token_type']);
        $this->assertSame(FixtureFactory::FIXTURE_REFRESH_TOKEN, $jsonResponse['jti']);
    }

    public function testActiveTokenWithInvalidHint()
    {
        $response = $this->handleIntrospectionRequest([
           'token' => $this->getRefreshToken(FixtureFactory::FIXTURE_REFRESH_TOKEN),
           'token_hint' => OAuth2TokenTypeHints::ACCESS_TOKEN,
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        $jsonResponse = json_decode($response->getContent(), true);

        $this->assertCount(1, $jsonResponse);
        $this->assertFalse($jsonResponse['active']);
    }

    public function testActiveTokenWithUnregisteredHint()
    {
        $response = $this->handleIntrospectionRequest([
            'token' => $this->getRefreshToken(FixtureFactory::FIXTURE_REFRESH_TOKEN),
            'token_hint' => 'foobar',
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        $jsonResponse = json_decode($response->getContent(), true);

        $this->assertCount(1, $jsonResponse);
        $this->assertFalse($jsonResponse['active']);
    }

    public function testRevokedToken()
    {
        $response = $this->handleIntrospectionRequest([
            'token' => $this->getAccessToken(FixtureFactory::FIXTURE_ACCESS_TOKEN_REVOKED),
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        $jsonResponse = json_decode($response->getContent(), true);

        $this->assertCount(1, $jsonResponse);
        $this->assertFalse($jsonResponse['active']);
    }

    public function testExpiredToken()
    {
        $response = $this->handleIntrospectionRequest([
            'token' => $this->getAccessToken(FixtureFactory::FIXTURE_ACCESS_TOKEN_EXPIRED),
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        $jsonResponse = json_decode($response->getContent(), true);

        $this->assertCount(1, $jsonResponse);
        $this->assertFalse($jsonResponse['active']);
    }

    public function testNotExistentToken()
    {
        $response = $this->handleIntrospectionRequest([
            'token' => 'foobar',
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        $jsonResponse = json_decode($response->getContent(), true);

        $this->assertCount(1, $jsonResponse);
        $this->assertFalse($jsonResponse['active']);
    }

    public function testUnauthorizedRequest()
    {
        $this->client->request('POST', '/introspect', [
            'token' => $this->getAccessToken(FixtureFactory::FIXTURE_ACCESS_TOKEN_PUBLIC),
        ]);
        $response = $this->client->getResponse();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        $jsonResponse = json_decode($response->getContent(), true);

        $this->assertSame('unauthorized_client', $jsonResponse['error']);
    }

    private function handleIntrospectionRequest(array $parameters): Response
    {
        $this->client->request('POST', '/introspect', $parameters, [], [
            'HTTP_AUTHORIZATION' => $this->getAuthorizationHeader(FixtureFactory::FIXTURE_ACCESS_TOKEN_PUBLIC),
        ]);

        return $this->client->getResponse();
    }

    private function getAuthorizationHeader($accessTokenId): string
    {
        return sprintf('Bearer %s', $this->getAccessToken($accessTokenId));
    }

    private function getAccessToken($accessTokenId): string
    {
        $accessToken = $this->client
            ->getContainer()
            ->get(AccessTokenManagerInterface::class)
            ->find($accessTokenId);

        return $accessToken ? TestHelper::generateJwtToken($accessToken) : '';
    }

    private function getRefreshToken($refreshTokenId): string
    {
        $refreshToken = $this->client
            ->getContainer()
            ->get(RefreshTokenManagerInterface::class)
            ->find($refreshTokenId);

        return $refreshToken ? TestHelper::generateEncryptedPayload($refreshToken) : '';
    }
}
