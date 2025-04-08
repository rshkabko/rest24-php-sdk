<?php

namespace Bitrix24\Contracts;

interface iBitrix24
{
    // Authorization and tokens
    public function setApplicationId(string $applicationId);

    public function getApplicationId(): string;

    public function setApplicationSecret(string $applicationSecret);

    public function getApplicationSecret(): string;

    public function setRedirectUri(string $redirectUri);

    public function getRedirectUri(): ?string;

    public function setDomain(string $domain);

    public function getDomain(): ?string;

    public function setAccessToken(string $accessToken);

    public function getAccessToken(): ?string;

    public function setRefreshToken(string $refreshToken);

    public function getRefreshToken(): string;

    public function setMemberId(string $memberId);

    public function getMemberId(): ?string;

    public function getFirstAccessToken(string $code): array;

    public function getNewAccessToken(): array;

    public function isAccessTokenExpire(): bool;

    // API calls
    public function call(string $methodName, array $additionalParameters = []);

    public function getMethodParameters();

    // Batch requests
    public function addBatchCall(string $method, array $parameters = [], callable $callback = null);

    public function hasBatchCalls(): bool;

    public function processBatchCalls(int $halt = 0, int $delay = 0);

    public function rawBatch(array $batch, int $halt = 0);

    // Webhook mode
    public function setWebhookUsage(bool $webhookUsage);

    public function getWebhookUsage(): bool;

    public function setWebhookSecret(string $webhookSecret);

    public function getWebhookSecret(): ?string;

    // Event callbacks
    public function setOnExpiredToken(callable $callback);

    public function setOnPortalRenamed(callable $callback);

    public function setOnCallApiMethod(callable $callback);

    // Retry and debug
    public function setRetriesToConnectCount(int $retriesCnt): self;

    public function getRetriesToConnectCount(): int;

    public function setRetriesToConnectTimeout(int $microseconds);

    public function getRetriesToConnectTimeout();

    public function setCustomCurlOptions(array $options): self;

    // Request info
    public function getRawRequest();

    public function getRequestInfo();

    public function getRawResponse();
}
