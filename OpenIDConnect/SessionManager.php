<?php

namespace Trikoder\Bundle\OAuth2Bundle\OpenIDConnect;

use DateTimeImmutable;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use LogicException;
use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Zend\Diactoros\Uri;

class SessionManager
{
    private const TOKEN_ATTRIBUTE_PREFIX = 'opbs_';
    private const COOKIE_NAME_PREFIX = 'opbs_';
    private $requestStack;
    private $tokenStorage;
    private $firewallMap;
    private $urlGenerator;
    private $checkSessionIframeRoute;

    public function __construct(RequestStack $requestStack, TokenStorageInterface $tokenStorage, FirewallMap $firewallMap, UrlGeneratorInterface $urlGenerator, $checkSessionIframeRoute = 'oauth2_check_session_iframe')
    {
        $this->requestStack = $requestStack;
        $this->tokenStorage = $tokenStorage;
        $this->firewallMap = $firewallMap;
        $this->urlGenerator = $urlGenerator;
        $this->checkSessionIframeRoute = $checkSessionIframeRoute;
    }

    public function computeSessionState(AuthorizationRequest $authRequest): string
    {
        $currentRequest = $this->requestStack->getCurrentRequest();
        if (!$currentRequest->hasSession()) {
            throw new LogicException('Ther is no current session, but OpenID Connect Session Management is enabled.');
        }

        $salt = $this->generateSalt();
        $data = [
            $authRequest->getClient()->getIdentifier(),
            $this->getOrigin($authRequest),
            $this->getBrowserState(),
            $salt,
        ];

        $hash = hash('sha256', implode(' ', $data));

        return implode('.', [$hash, $salt]);
    }

    private function getBrowserState(): string
    {
        if (!$this->hasBrowserState()) {
            $this->resetBrowserState();
        }

        return $this->getToken()->getAttribute($this->getBrowserStateAttribute());
    }

    private function hasBrowserState(): bool
    {
        return $this->getToken()->hasAttribute($this->getBrowserStateAttribute());
    }

    private function getToken(): TokenInterface
    {
        if (null === $token = $this->tokenStorage->getToken()) {
            throw new LogicException('No token available');
        }

        return $token;
    }

    private function getBrowserStateAttribute(): string
    {
        return self::TOKEN_ATTRIBUTE_PREFIX . $this->getFirewallContext();
    }

    private function getFirewallContext(): string
    {
        $firewallConfig = $this->firewallMap->getFirewallConfig($this->requestStack->getCurrentRequest());

        return $firewallConfig->getContext() ?? $firewallConfig->getName();
    }

    public function resetBrowserState(): void
    {
        $this->getToken()->setAttribute($this->getBrowserStateAttribute(), $this->generateBrowserState());
    }

    private function generateBrowserState(): string
    {
        return sha1(random_bytes(32));
    }

    private function getOrigin(AuthorizationRequest $authRequest): string
    {
        $originUri = new Uri($authRequest->getRedirectUri());

        return $originUri->getScheme() . '://' . $originUri->getAuthority();
    }

    private function generateSalt(): string
    {
        return sha1(random_bytes(32));
    }

    public function getBrowserStateCookie(): Cookie
    {
        $expire = (new DateTimeImmutable())->modify('+1 day');
        $path = $this->urlGenerator->generate($this->checkSessionIframeRoute);
        $cookie = Cookie::create($this->getBrowserStateCookieName(), $this->getBrowserState(), $expire, $path, null, null, false, false, Cookie::SAMESITE_LAX);

        return $cookie;
    }

    public function getBrowserStateCookieName(): string
    {
        return self::COOKIE_NAME_PREFIX . $this->getFirewallContext();
    }
}
