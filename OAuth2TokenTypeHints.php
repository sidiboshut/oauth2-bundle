<?php

namespace Trikoder\Bundle\OAuth2Bundle;

final class OAuth2TokenTypeHints
{
    /**
     * @see https://tools.ietf.org/html/rfc7009#section-4.1.2.2
     *
     * @var string
     */
    public const ACCESS_TOKEN = 'access_token';

    /**
     * @see https://tools.ietf.org/html/rfc7009#section-4.1.2.2
     *
     * @var string
     */
    public const REFRESH_TOKEN = 'refresh_token';
}
