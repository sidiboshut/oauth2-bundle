<?php

namespace Trikoder\Bundle\OAuth2Bundle\Controller;

use Symfony\Component\HttpFoundation\Response;
use Trikoder\Bundle\OAuth2Bundle\OpenIDConnect\SessionManager;

final class SessionManagementController
{
    private $sessionManager;

    public function __construct(SessionManager $sessionManager)
    {
        $this->sessionManager = $sessionManager;
    }

    public function indexAction(): Response
    {
        return new Response($this->getCheckSessionBody(), 200);
    }

    private function getCheckSessionBody()
    {
        $template = <<< 'eot'
<html>
    <head>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jsSHA/2.3.1/sha256.js"></script>
        <script>
            window.addEventListener("message", receiveMessage, false);

            function receiveMessage(e){
                var message_parts = e.data.split(' ');
                if (message_parts.length !== 2) {
                    postMessage('error', e.origin);
                }

                var client_id = message_parts[0];
                var session_state = message_parts[1];

                var session_state_parts = session_state.split('.');
                if (session_state_parts.length !== 2) {
                    postMessage('error', e.origin);
                }
                var salt = session_state_parts[1];
                var opbs = get_op_browser_state();

                var shaObj = new jsSHA("SHA-256", "TEXT")
                shaObj.update(client_id + ' ' + e.origin + ' ' + opbs + ' ' + salt);
                var ss = shaObj.getHash('HEX') + "." + salt;

                var stat = 'changed';
                if (session_state == ss) {
                    stat = 'unchanged';
                }

                e.source.postMessage(stat, e.origin);
            };

            function get_op_browser_state() {
                var pairs = document.cookie.split(/; */);

                for (var i = 0; i < pairs.length; i++) {
                    var pair = pairs[i];
                    var eq_idx = pair.indexOf('=');

                    // skip things that don't look like key=value
                    if (eq_idx < 0) {
                        continue;
                    }

                    var key = pair.substr(0, eq_idx).trim()
                    if (@@cookieName@@ != key) {
                        continue;
                    }

                    var val = pair.substr(++eq_idx, pair.length).trim();
                    if ('"' == val[0]) {
                        val = val.slice(1, -1);
                    }
                    return decodeURIComponent(val);
                }

                return '';
            };
        </script>
    </head>
    <body></body>
</html>
eot;

        $body = str_replace('@@cookieName@@', json_encode($this->sessionManager->getBrowserStateCookieName()), $template);

        return $body;
    }
}
