<?php

namespace Trikoder\Bundle\OAuth2Bundle\Security\Http\Logout;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;
use Trikoder\Bundle\OAuth2Bundle\OpenIDConnect\SessionManager;

class ResetBrowserStatusLogoutHandler implements LogoutHandlerInterface
{
    private $sessionManager;

    public function __construct(SessionManager $sessionManager)
    {
        $this->sessionManager = $sessionManager;
    }

    public function logout(Request $request, Response $response, TokenInterface $token)
    {
        $this->sessionManager->resetBrowserState();
        $response->headers->setCookie($this->sessionManager->getBrowserStateCookie());
    }
}
