<?php

namespace Trikoder\Bundle\OAuth2Bundle\Controller;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Bridge\PsrHttpMessage\HttpFoundationFactoryInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Response as HttpFoundationResponse;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Trikoder\Bundle\OAuth2Bundle\Event\AuthorizationRequestResolveEvent;
use Trikoder\Bundle\OAuth2Bundle\League\Entity\User;
use Trikoder\Bundle\OAuth2Bundle\OAuth2Events;
use Trikoder\Bundle\OAuth2Bundle\OpenIDConnect\SessionManager;
use Zend\Diactoros\Response;
use Zend\Diactoros\Uri;

final class AuthorizationController
{
    private const TOKEN_ATTRIBUTE_BROWSER_STATE = 'op_browser_state';
    private const PARAM_PROMPT = 'prompt';
    private const PROMPT_NONE = 'none';

    /**
     * @var AuthorizationServer
     */
    private $server;

    /**
     * @var AuthorizationCheckerInterface
     */
    private $authorizationChecker;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * @var SessionManager
     */
    private $sessionManager;

    /**
     * @var HttpFoundationFactoryInterface
     */
    private $httpFoundationFactory;

    public function __construct(AuthorizationServer $server, AuthorizationCheckerInterface $authorizationChecker, TokenStorageInterface $tokenStorage, EventDispatcherInterface $eventDispatcher, SessionManager $sessionManager = null, HttpFoundationFactoryInterface $httpFoundationFactory = null)
    {
        $this->server = $server;
        $this->authorizationChecker = $authorizationChecker;
        $this->tokenStorage = $tokenStorage;
        $this->eventDispatcher = $eventDispatcher;
        $this->sessionManager = $sessionManager;
        $this->httpFoundationFactory = $httpFoundationFactory;
    }

    public function indexAction(ServerRequestInterface $serverRequest)
    {
        if (!$this->authorizationChecker->isGranted('IS_AUTHENTICATED_REMEMBERED')) {
            throw new LogicException('There is no logged in user. Review your security config to protect this endpoint.');
        }

        $serverResponse = new Response();

        try {
            $authRequest = $this->server->validateAuthorizationRequest($serverRequest);
            $authRequest->setUser($this->getUserEntity());

            $event = $this->eventDispatcher->dispatch(
                OAuth2Events::AUTHORIZATION_REQUEST_RESOLVE,
                new AuthorizationRequestResolveEvent($authRequest)
            );

            if (AuthorizationRequestResolveEvent::AUTHORIZATION_PENDING === $event->getAuhorizationResolution()
                && $this->userInteractionAllowed($serverRequest)
            ) {
                return $serverResponse->withStatus(302)->withHeader('Location', $event->getDecisionUri());
            }

            if (AuthorizationRequestResolveEvent::AUTHORIZATION_APPROVED === $event->getAuhorizationResolution()) {
                $authRequest->setAuthorizationApproved(true);
            }

            return $this->completeAuthorizationRequestWithSessionInfo($authRequest);
        } catch (OAuthServerException $e) {
            return $e->generateHttpResponse($serverResponse);
        }
    }

    private function getUserEntity(): User
    {
        $token = $this->tokenStorage->getToken();
        if (null === $token) {
            throw new LogicException('There is no security token available. Review your security config to protect endpoint.');
        }

        $user = $token->getUser();
        $username = $user instanceof UserInterface ? $user->getUsername() : (string) $user;

        $userEntity = new User();
        $userEntity->setIdentifier($username);

        return $userEntity;
    }

    private function userInteractionAllowed(ServerRequestInterface $serverRequest): bool
    {
        return
            !isset($serverRequest->getQueryParams()[self::PARAM_PROMPT])
            || self::PROMPT_NONE !== $serverRequest->getQueryParams()[self::PARAM_PROMPT]
        ;
    }

    private function completeAuthorizationRequestWithSessionInfo(AuthorizationRequest $authRequest)
    {
        $authorizationResponse = $this->server->completeAuthorizationRequest($authRequest, new Response());

        if (!$this->isOpenIDConnectRequest($authRequest)) {
            return $authorizationResponse;
        }

        if (!$authorizationResponse->hasHeader('location')) {
            return $authorizationResponse;
        }

        if (null === $this->sessionManager) {
            return $authorizationResponse;
        }

        $sessionState = $this->sessionManager->computeSessionState($authRequest);

        return $this->respondWithSessionState($authorizationResponse, $sessionState);
    }

    private function isOpenIDConnectRequest(AuthorizationRequest $authRequest): bool
    {
        foreach ($authRequest->getScopes() as $scope) {
            if ('openid' === $scope->getIdentifier()) {
                return true;
            }
        }

        return false;
    }

    /**
     * @todo Remove http foundation conversion once samesite parameter is not ignored by psr-http-message-bridge
     */
    private function respondWithSessionState(ResponseInterface $authorizationResponse, string $sessionState): HttpFoundationResponse
    {
        $location = $authorizationResponse->getHeaderLine('location');
        $locationUri = new Uri($location);
        $queryData = [];
        parse_str($locationUri->getQuery(), $queryData);

        if (!array_key_exists('error', $queryData)) {
            $queryData['session_state'] = $sessionState;
        }

        $newLocationUri = $locationUri->withQuery(http_build_query($queryData));
        $cookie = $this->sessionManager->getBrowserStateCookie();

        $response = $this->httpFoundationFactory->createResponse(
            $authorizationResponse->withHeader('location', (string) $newLocationUri)
        );

        $response->headers->setCookie($cookie);

        return $response;
    }
}
