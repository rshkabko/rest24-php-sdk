Bitrix24 REST API SDK
================

## Installation ##
```bash
composer require flamix/bitrix24-php-sdk
```

## Example ##
``` php
<?php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// create a log channel
$log = new Logger('bitrix24');
$log->pushHandler(new StreamHandler('path/to/your.log', Logger::DEBUG));


// init lib
$obB24App = new \Bitrix24\Bitrix24(false, $log);
$obB24App->setApplicationScope($arParams['B24_APPLICATION_SCOPE']);
$obB24App->setApplicationId($arParams['B24_APPLICATION_ID']);
$obB24App->setApplicationSecret($arParams['B24_APPLICATION_SECRET']);
 
// set user-specific settings
$obB24App->setDomain($arParams['DOMAIN']);
$obB24App->setMemberId($arParams['MEMBER_ID']);
$obB24App->setAccessToken($arParams['AUTH_ID']);
$obB24App->setRefreshToken($arParams['REFRESH_ID']);

// get information about current user from bitrix24
$obB24User = new \Bitrix24\User\User($obB24App);
$arCurrentB24User = $obB24User->current();
```
