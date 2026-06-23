Rest24 — Bitrix24 REST API SDK
================

## Installation ##
```bash
composer require flamix/rest24-php-sdk
```

## Example ##
``` php
<?php
use Bitrix24\Bitrix24;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// PSR-3 logger (optional)
$log = new Logger('bitrix24');
$log->pushHandler(new StreamHandler('path/to/your.log', Logger::DEBUG));

// init lib
$b24 = new Bitrix24(false, $log);
$b24->setApplicationId('local.xxxxxxxx');
$b24->setApplicationSecret('xxxxxxxxxxxxxxxx');

// set user-specific settings
$b24->setDomain('example.bitrix24.ru');
$b24->setMemberId('xxxxxxxxxxxxxxxx');
$b24->setAccessToken('xxxxxxxxxxxxxxxx');
$b24->setRefreshToken('xxxxxxxxxxxxxxxx');

// call any REST method directly
$user = $b24->call('user.current', ['state' => $b24->getSecuritySignSalt()]);

$result = $b24->call('crm.lead.add', [
    'fields' => [
        'TITLE' => 'New lead',
        'NAME'  => 'John',
    ],
]);
$leadId = $result['result'];
```
