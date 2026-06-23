<?php

namespace Bitrix24\Traits;

use Bitrix24\Exceptions\Bitrix24Exception;

/**
 * Application credentials (domain, tokens, app id/secret, redirect, member id,
 * oAuth server) and OAuth token lifecycle (issue / refresh / expiration check,
 * scopes, available methods, security sign salt).
 *
 * Relies on the host class providing executeRequest() and
 * handleBitrix24APILevelErrors() (the HTTP transport layer).
 */
trait OAuth
{
    /**
     * @var string oAuth server
     */
    protected string $oauthServer = 'oauth.bitrix.info';

    /**
     * @var string access token
     */
    protected string $accessToken;

    /**
     * @var string refresh token
     */
    protected string $refreshToken;

    /**
     * @var string domain
     */
    protected string $domain;

    /**
     * @var string application id
     */
    protected string $applicationId;

    /**
     * @var string application secret
     */
    protected string $applicationSecret;

    /**
     * @var string redirect URI from application settings
     */
    protected string $redirectUri;

    /**
     * @var string portal GUID
     */
    protected string $memberId;

    /**
     * Get a random string to sign protected api-call. Use salt for argument "state" in secure api-call
     * random string is a result of mt_rand function
     *
     * @return int
     */
    public function getSecuritySignSalt(): string
    {
        return mt_rand();
    }

    /**
     * Change default oAuth server.
     *
     * @param  string  $url
     * @return $this
     */
    public function setAuthServer(string $url): self
    {
        $this->oauthServer = $url;
        return $this;
    }

    /**
     * Get new access token
     *
     * @return array
     *
     * @throws Exception
     */
    public function getNewAccessToken(): array
    {
        $applicationId = $this->getApplicationId();
        $applicationSecret = $this->getApplicationSecret();
        $refreshToken = $this->getRefreshToken();
        $redirectUri = $this->getRedirectUri();

        if (null === $applicationId) {
            throw new Bitrix24Exception('application id not found, you must call setApplicationId method before');
        } elseif (null === $applicationSecret) {
            throw new Bitrix24Exception('application id not found, you must call setApplicationSecret method before');
        } elseif (null === $refreshToken) {
            throw new Bitrix24Exception('application id not found, you must call setRefreshToken method before');
        }

        $url = "https://{$this->oauthServer}/oauth/token/?".http_build_query([
                'grant_type' => 'refresh_token',
                'client_id' => $applicationId,
                'client_secret' => $applicationSecret,
                'refresh_token' => $refreshToken,
            ]);

        if ($redirectUri) {
            $url .= '&redirect_uri='.urlencode($redirectUri);
        }

        $requestResult = $this->executeRequest($url);

        // handling bitrix24 api-level errors
        $this->handleBitrix24APILevelErrors($requestResult, 'refresh access token');

        return $requestResult;
    }

    /**
     * Get application id
     *
     * @return string
     */
    public function getApplicationId(): string
    {
        return $this->applicationId;
    }

    /**
     * Set application id
     *
     * @param  string  $applicationId
     *
     * @return self
     */
    public function setApplicationId(string $applicationId): self
    {
        $this->applicationId = $applicationId;
        return $this;
    }

    /**
     * Get application secret
     *
     * @return string
     */
    public function getApplicationSecret(): string
    {
        return $this->applicationSecret;
    }

    /**
     * Set application secret
     *
     * @param  string  $applicationSecret
     *
     * @return self
     *
     */
    public function setApplicationSecret(string $applicationSecret): self
    {
        $this->applicationSecret = $applicationSecret;
        return $this;
    }

    /**
     * Get refresh token
     *
     * @return string
     */
    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    /**
     * Set refresh token
     *
     * @param $refreshToken
     *
     * @return self
     *
     */
    public function setRefreshToken(string $refreshToken): self
    {
        $this->refreshToken = $refreshToken;
        return $this;
    }

    /**
     * Get redirect URI
     *
     * @return string | null
     */
    public function getRedirectUri(): ?string
    {
        return $this->redirectUri ?? null;
    }

    /**
     * Set redirect URI
     *
     * @param  string  $redirectUri
     *
     * @return self
     *
     */
    public function setRedirectUri(string $redirectUri): self
    {
        $this->redirectUri = $redirectUri;
        return $this;
    }

    /**
     * Get domain
     *
     * @return string | null
     */
    public function getDomain(): ?string
    {
        return $this->domain ?? null;
    }

    /**
     * Set domain
     *
     * @param $domain
     *
     * @return self
     *
     */
    public function setDomain(string $domain): self
    {
        $this->domain = $domain;
        return $this;
    }

    /**
     * Get memeber ID
     *
     * @return string | null
     */
    public function getMemberId(): ?string
    {
        return $this->memberId ?? null;
    }

    /**
     * Set member ID — portal GUID
     *
     * @param  string  $memberId
     *
     * @return self
     */
    public function setMemberId(string $memberId): self
    {
        $this->memberId = $memberId;
        return $this;
    }

    /**
     * Get access token
     *
     * @return string | null
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken ?? null;
    }

    /**
     * Set access token
     *
     * @param  string  $accessToken
     *
     * @return self
     *
     */
    public function setAccessToken(string $accessToken): self
    {
        $this->accessToken = $accessToken;
        return $this;
    }

    /**
     * Authorize and get first access token
     *
     * @param $code
     *
     * @return array
     *
     * @throws Exception
     */
    public function getFirstAccessToken($code): array
    {
        $applicationId = $this->getApplicationId();
        $applicationSecret = $this->getApplicationSecret();
        $redirectUri = $this->getRedirectUri();

        if (null === $applicationId) {
            throw new Bitrix24Exception('application id not found, you must call setApplicationId method before');
        } elseif (null === $applicationSecret) {
            throw new Bitrix24Exception('application id not found, you must call setApplicationSecret method before');
        } elseif (null === $redirectUri) {
            throw new Bitrix24Exception('application redirect URI not found, you must call setRedirectUri method before');
        }

        $url = "https://{$this->oauthServer}/oauth/token/?".http_build_query([
                'grant_type' => 'authorization_code',
                'client_id' => $applicationId,
                'client_secret' => $applicationSecret,
                'code' => $code,
            ]);

        $requestResult = $this->executeRequest($url);

        // handling bitrix24 api-level errors
        $this->handleBitrix24APILevelErrors($requestResult, 'get first access token');

        return $requestResult;
    }

    /**
     * Check is access token expire, call list of all available api-methods from B24 portal with current access token
     * if we have an error code expired_token then return true else return false
     *
     * @return boolean
     * @throws Exception
     *
     */
    public function isAccessTokenExpire(): bool
    {
        $isTokenExpire = false;
        $accessToken = $this->getAccessToken();
        $domain = $this->getDomain();

        if (null === $domain) {
            throw new Bitrix24Exception('domain not found, you must call setDomain method before');
        } elseif (null === $accessToken) {
            throw new Bitrix24Exception('application id not found, you must call setAccessToken method before');
        }
        $url = "https://{$this->oauthServer}/rest/app.info?auth={$accessToken}";
        $requestResult = $this->executeRequest($url);

        if (isset($requestResult['error'])) {
            if (in_array($requestResult['error'], ['expired_token', 'invalid_token', 'WRONG_TOKEN'], false)) {
                $isTokenExpire = true;
            } else {
                // handle other errors
                $this->handleBitrix24APILevelErrors($requestResult, 'app.info');
            }
        }

        return $isTokenExpire;
    }

    /**
     * Get list of all methods available for current application
     *
     * @param  array | null  $applicationScope
     * @param  bool  $isFull
     *
     * @return array
     *
     * @throws Exception
     */
    public function getAvailableMethods(array $applicationScope = [], bool $isFull = false)
    {
        $accessToken = $this->getAccessToken();
        $domain = $this->getDomain();

        if (null === $domain) {
            throw new Bitrix24Exception('domain not found, you must call setDomain method before');
        } elseif (null === $accessToken) {
            throw new Bitrix24Exception('application id not found, you must call setAccessToken method before');
        }

        $url = "https://{$domain}/rest/methods.json?auth={$accessToken}";

        if (true === $isFull) {
            $url .= '&full=true';
        }

        if (count(array_unique($applicationScope)) > 0) {
            $scope = '&scope='.implode(',', array_map('urlencode', array_unique($applicationScope)));
        }

        if ($scope ?? null) {
            $url .= $scope;
        }

        return $this->executeRequest($url);
    }

    /**
     * get list of scope for current application from bitrix24 api
     *
     * @param  bool  $isFull
     *
     * @return array
     * @throws Exception
     */
    public function getScope($isFull = false)
    {
        $accessToken = $this->getAccessToken();
        $domain = $this->getDomain();

        if (null === $domain) {
            throw new Bitrix24Exception('domain not found, you must call setDomain method before');
        } elseif (null === $accessToken) {
            throw new Bitrix24Exception('application id not found, you must call setAccessToken method before');
        }

        $url = "https://{$domain}/rest/scope.json?auth={$accessToken}";
        if ($isFull) {
            $url .= '&full=true';
        }

        return $this->executeRequest($url);
    }
}
