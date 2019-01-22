<?php

namespace Trikoder\Bundle\OAuth2Bundle\Controller;

use InvalidArgumentException;
use Lcobucci\JWT\Parser;
use League\OAuth2\Server\CryptTrait;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Trikoder\Bundle\OAuth2Bundle\Manager\AccessTokenManagerInterface;
use Trikoder\Bundle\OAuth2Bundle\Manager\RefreshTokenManagerInterface;
use Trikoder\Bundle\OAuth2Bundle\Model\AccessToken;
use Trikoder\Bundle\OAuth2Bundle\Model\RefreshToken;
use Trikoder\Bundle\OAuth2Bundle\Model\Scope;
use Trikoder\Bundle\OAuth2Bundle\OAuth2TokenTypeHints;

final class IntrospectionController
{
    use CryptTrait;

    private $authorizationChecker;
    private $accessTokenManager;
    private $refreshTokenManager;

    public function __construct(AuthorizationCheckerInterface $authorizationChecker, AccessTokenManagerInterface $accessTokenManager, RefreshTokenManagerInterface $refreshTokenManager, $encryptionKey)
    {
        $this->authorizationChecker = $authorizationChecker;
        $this->accessTokenManager = $accessTokenManager;
        $this->refreshTokenManager = $refreshTokenManager;
        $this->encryptionKey = $encryptionKey;
    }

    public function indexAction(Request $request): JsonResponse
    {
        if (!$this->authorizationChecker->isGranted('IS_AUTHENTICATED_REMEMBERED')) {
            return new JsonResponse(['error' => 'unauthorized_client'], 401);
        }

        if (!$request->request->has('token')) {
            return new JsonResponse(['error' => 'invalid_request'], 400);
        }

        $token = $request->request->get('token');
        $tokenHint = $request->request->get('token_hint');

        $tokenData = $this->extractTokenData($token, $tokenHint) + $this->buildInactiveData();

        return new JsonResponse($tokenData);
    }

    private function extractTokenData(string $token, ?string $tokenHint): array
    {
        switch ($tokenHint) {
            case OAuth2TokenTypeHints::ACCESS_TOKEN:
                return $this->extractAccessTokenData($token);
            case OAuth2TokenTypeHints::REFRESH_TOKEN:
                return $this->extractRefreshTokenData($token);
            case null:
                return $this->extractAccessTokenData($token) + $this->extractRefreshTokenData($token);
            default:
                return [];
        }
    }

    private function extractAccessTokenData(string $token): array
    {
        try {
            $identifier = (new Parser())->parse($token)->getClaim('jti');
        } catch (InvalidArgumentException $e) {
            return [];
        }

        $accessToken = $this->accessTokenManager->find($identifier);

        if (null === $accessToken || !$this->isAccessTokenActive($accessToken)) {
            return [];
        }

        $data = [
            'active' => true,
            'client_id' => $accessToken->getClient()->getIdentifier(),
            'token_type' => 'bearer',
            'exp' => $accessToken->getExpiry()->getTimestamp(),
            'jti' => $accessToken->getIdentifier(),
        ];

        $scopes = $accessToken->getScopes();
        if (!empty($scopes)) {
            $data['scope'] = $this->scopesToString(...$scopes);
        }

        $userIdentifier = $accessToken->getUserIdentifier();
        if (!empty($userIdentifier)) {
            $data['sub'] = $accessToken->getUserIdentifier();
        }

        return $data;
    }

    private function isAccessTokenActive(AccessToken $accessToken): bool
    {
        if ($accessToken->isRevoked()) {
            return false;
        }

        if (time() > $accessToken->getExpiry()->getTimestamp()) {
            return false;
        }

        return true;
    }

    private function buildInactiveData(): array
    {
        return ['active' => false];
    }

    private function scopesToString(Scope ...$scopes): string
    {
        return implode(
            ' ',
            array_map(
                function (Scope $scope) {
                    return (string) $scope;
                },
                $scopes
            )
        );
    }

    private function extractRefreshTokenData(string $token): array
    {
        try {
            $tokenData = json_decode($this->decrypt($token), true);
        } catch (\LogicException $e) {
            return [];
        }

        if (!\is_array($tokenData) || !isset($tokenData['refresh_token_id'])) {
            return [];
        }
        $identifier = $tokenData['refresh_token_id'];

        $refreshToken = $this->refreshTokenManager->find($identifier);

        if (null === $refreshToken || !$this->isRefreshTokenActive($refreshToken)) {
            return [];
        }

        $data = [
            'active' => true,
            'client_id' => $refreshToken->getAccessToken()->getClient()->getIdentifier(),
            'token_type' => 'bearer',
            'exp' => $refreshToken->getExpiry()->getTimestamp(),
            'jti' => $refreshToken->getIdentifier(),
        ];

        $scopes = $refreshToken->getAccessToken()->getScopes();
        if (!empty($scopes)) {
            $data['scope'] = $this->scopesToString(...$scopes);
        }

        $userIdentifier = $refreshToken->getAccessToken()->getUserIdentifier();
        if (!empty($userIdentifier)) {
            $data['sub'] = $refreshToken->getAccessToken()->getUserIdentifier();
        }

        return $data;
    }

    private function isRefreshTokenActive(RefreshToken $refreshToken): bool
    {
        if ($refreshToken->isRevoked()) {
            return false;
        }

        if (time() > $refreshToken->getExpiry()->getTimestamp()) {
            return false;
        }

        return true;
    }
}
