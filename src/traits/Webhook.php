<?php

namespace Bitrix24\Traits;

use Bitrix24\Exceptions\Bitrix24Exception;

trait Webhook
{
    /**
     * @var bool if true - webhook will be used in API calls (without access_token)
     */
    protected bool $webhook_usage = false;

    /**
     * @var string webhook secret identifier
     */
    protected string $webhook_secret;


    /**
     * Set whether we using webhook or application in API calls
     * If true - use webhook in API call
     *
     * @param  bool  $webhook_usage_boolean
     *
     * @return self
     */
    public function setWebhookUsage(bool $webhook_usage_boolean): self
    {
        $this->webhook_usage = $webhook_usage_boolean;
        return $this;
    }

    /**
     * Return whether we using webhook or application in API calls
     *
     * @return bool
     */
    public function getWebhookUsage(): bool
    {
        return $this->webhook_usage;
    }

    /**
     * Set webhook secret to use in API calls
     *
     * @param  string  $webhook_secret
     *
     * @return bool
     */
    public function setWebhookSecret($webhook_secret)
    {
        $this->webhook_secret = $webhook_secret;

        return true;
    }

    /**
     * Return string with webhook secret
     *
     * @return null | string
     */
    public function getWebhookSecret(): ?string
    {
        return $this->webhook_secret ?? null;
    }

    /**
     * Execute Bitrix24 REST API method using webhook
     *
     * @param  string  $methodName
     * @param  array  $additionalParameters
     *
     * @return array
     * @throws Exception
     */
    protected function _call_webhook(string $methodName, array $additionalParameters = [])
    {
        if (null === $this->getDomain()) {
            throw new Bitrix24Exception('domain not found, you must call setDomain method before');
        }

        if (null === $this->getWebhookSecret()) {
            throw new Bitrix24Exception('no webhook secret provided, you must call setWebhookSecret method before');
        }

        $url = 'https://'.$this->domain.'/rest/'.$this->getWebhookSecret().'/'.$methodName;

        // save method parameters for debug
        $this->methodParameters = $additionalParameters;

        // execute request
        $this->log->info('call bitrix24 method', [
            'BITRIX24_WEBHOOK_URL' => $url,
            'BITRIX24_DOMAIN' => $this->domain,
            'METHOD_NAME' => $methodName,
            'METHOD_PARAMETERS' => $additionalParameters,
        ]);
        $requestResult = $this->executeRequest($url, $additionalParameters);

        // check errors and throw exception if errors exists
        $this->handleBitrix24APILevelErrors($requestResult, $methodName, $additionalParameters);

        return $requestResult;
    }
}
