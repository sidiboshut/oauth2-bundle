<?php

namespace Trikoder\Bundle\OAuth2Bundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Trikoder\Bundle\OAuth2Bundle\Manager\ClientManagerInterface;
use Trikoder\Bundle\OAuth2Bundle\Model\Client;
use Trikoder\Bundle\OAuth2Bundle\Model\Grant;
use Trikoder\Bundle\OAuth2Bundle\Model\RedirectUri;
use Trikoder\Bundle\OAuth2Bundle\Model\Scope;

final class CreateClientCommand extends Command
{
    protected static $defaultName = 'trikoder:oauth2:create-client';

    private $clientManager;

    public function __construct(ClientManagerInterface $clientManager)
    {
        parent::__construct();

        $this->clientManager = $clientManager;
    }

    protected function configure()
    {
        $this
            ->setDescription('Creates a new oAuth2 client')
            ->addOption(
                'redirect-uri',
                null,
                InputOption::VALUE_OPTIONAL | InputOption::VALUE_IS_ARRAY,
                'Sets redirect uri for client. Use this option multiple times to set multiple redirect URIs.',
                null
            )
            ->addOption(
                'grant-type',
                null,
                InputOption::VALUE_OPTIONAL | InputOption::VALUE_IS_ARRAY,
                'Sets allowed grant type for client. Use this option multiple times to set multiple grant types.',
                null
            )
            ->addOption(
                'scope',
                null,
                InputOption::VALUE_OPTIONAL | InputOption::VALUE_IS_ARRAY,
                'Sets allowed scope for client. Use this option multiple times to set multiple scopes.',
                null
            )
            ->addArgument(
                'identifier',
                InputArgument::OPTIONAL,
                'The client identifier'
            )
            ->addArgument(
                'secret',
                InputArgument::OPTIONAL,
                'The client secret'
            )
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $io = new SymfonyStyle($input, $output);
        $client = $this->buildClientFromInput($input);
        $this->clientManager->save($client);
        $io->success('New oAuth2 client created successfully.');

        $headers = ['Identifier', 'Secret'];
        $rows = [
            [$client->getIdentifier(), $client->getSecret()],
        ];
        $io->table($headers, $rows);

        return 0;
    }

    private function buildClientFromInput(InputInterface $input)
    {
        $identifier = $input->getArgument('identifier') ?? hash('md5', random_bytes(16));
        $secret = $input->getArgument('secret') ?? hash('sha512', random_bytes(32));

        $client = new Client($identifier, $secret);
        $client->setActive(true);

        $redirectUris = array_map(
            function (string $redirectUri) { return new RedirectUri($redirectUri); },
            $input->getOption('redirect-uri')
        );
        $client->setRedirectUris(...$redirectUris);

        $grants = array_map(
            function (string $grant) { return new Grant($grant); },
            $input->getOption('grant-type')
        );
        $client->setGrants(...$grants);

        $scopes = array_map(
            function (string $scope) { return new Scope($scope); },
            $input->getOption('scope')
        );
        $client->setScopes(...$scopes);

        return $client;
    }
}
